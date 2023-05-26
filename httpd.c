#include "httpd.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>

#define MAX_CONNECTIONS 1000
#define BUF_SIZE 65535
#define QUEUE_SIZE 1000000

static int listenfd;
int *clients;
static void start_server(const char *);
static void respond(int, SSL *);

static char *buf;

// Client request
char *method, // "GET" or "POST"
    *uri,     // "/index.html" things before '?'
    *qs,      // "a=1&b=2" things after  '?'
    *prot,    // "HTTP/1.1"
    *payload; // for POST

int payload_size;

/*
 * Prepare a SSL context for use by the server
 */
static SSL_CTX *get_server_context(const char *ca_pem, const char *cert_pem, const char *key_pem) {
  SSL_CTX *ctx;

  /* Get a default context */
  if (!(ctx = SSL_CTX_new(SSLv23_server_method()))) {
    fprintf(stderr, "SSL_CTX_new failed\n");
    return NULL;
  }

  /* Set the CA file location for the server */
  if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1) {
    fprintf(stderr, "Could not set the CA file location\n");
    SSL_CTX_free(ctx);
    return NULL;
  }

  /* Load the client's CA file location as well */
  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_pem));

  /* Set the server's certificate signed by the CA */
  if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "Could not set the server's certificate\n");
    SSL_CTX_free(ctx);
    return NULL;
  }

  /* Set the server's key for the above certificate */
  if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1) {
    fprintf(stderr, "Could not set the server's key\n");
    SSL_CTX_free(ctx);
    return NULL;
  }

  /* We've loaded both certificate and the key, check if they match */
  if (SSL_CTX_check_private_key(ctx) != 1) {
    fprintf(stderr, "Server's certificate and the key don't match\n");
    SSL_CTX_free(ctx);
    return NULL;
  }

  /* We won't handle incomplete read/writes due to renegotiation */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* Specify that we need to verify the client as well */
  SSL_CTX_set_verify(ctx,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     NULL);

  /* We accept only certificates signed only by the CA himself */
  SSL_CTX_set_verify_depth(ctx, 1);

  /* Done, return the context */
  return ctx;
}

void serve_forever(const char *PORT, const char *ca_pem, const char *cert_pem, const char *key_pem) {
  struct sockaddr_in clientaddr;
  socklen_t addrlen;

  int slot = 0;

  SSL_CTX *ctx;
  SSL *ssl;
  int rc, len;

  /* Initialize OpenSSL */
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();

  printf("Server started %shttp://127.0.0.1:%s%s\n", "\033[92m", PORT,
         "\033[0m");

  /* Get a server context for our use */
  if (!(ctx = get_server_context(ca_pem, cert_pem, key_pem))) {
    exit(0);
  }

  // create shared memory for client slot array
  clients = mmap(NULL, sizeof(*clients) * MAX_CONNECTIONS,
                 PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);

  // Setting all elements to -1: signifies there is no client connected
  int i;
  for (i = 0; i < MAX_CONNECTIONS; i++)
    clients[i] = -1;
  start_server(PORT);

  // Ignore SIGCHLD to avoid zombie threads
  signal(SIGCHLD, SIG_IGN);

  // ACCEPT connections
  while (1) {
    addrlen = sizeof(clientaddr);
    clients[slot] = accept(listenfd, (struct sockaddr *)&clientaddr, &addrlen);

    /* Get an SSL handle from the context */
    if (!(ssl = SSL_new(ctx))) {
      fprintf(stderr, "%s", "Could not get an SSL handle from the context\n");
      close(clients[slot]);
      continue;
    }

    /* Associate the newly accepted connection with this handle */
    SSL_set_fd(ssl, clients[slot]);

    /* Now perform handshake */
    if ((rc = SSL_accept(ssl)) != 1) {
      fprintf(stderr, "Could not perform SSL handshake\n");
      if (rc != 0) {
        SSL_shutdown(ssl);
      }
      SSL_free(ssl);
      continue;
    } else {
      fprintf(stderr, "SSL handshake successful with %s:%d\n", inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
      if (clients[slot] < 0) {
        perror("accept() error");
        exit(1);
      } else {
        if (fork() == 0) {
          close(listenfd);
          respond(slot, ssl);
          close(clients[slot]);
          clients[slot] = -1;
          exit(0);
        } else {
          close(clients[slot]);
        }
      }
    }

    while (clients[slot] != -1)
      slot = (slot + 1) % MAX_CONNECTIONS;

    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
}

// start server
void start_server(const char *port) {
  struct addrinfo hints, *res, *p;

  // getaddrinfo for host
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if (getaddrinfo(NULL, port, &hints, &res) != 0) {
    perror("getaddrinfo() error");
    exit(1);
  }
  // socket and bind
  for (p = res; p != NULL; p = p->ai_next) {
    int option = 1;
    listenfd = socket(p->ai_family, p->ai_socktype, 0);
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
    if (listenfd == -1)
      continue;
    if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
      break;
  }
  if (p == NULL) {
    perror("socket() or bind()");
    exit(1);
  }

  freeaddrinfo(res);

  // listen for incoming connections
  if (listen(listenfd, QUEUE_SIZE) != 0) {
    perror("listen() error");
    exit(1);
  }
}

// get request header by name
char *request_header(const char *name) {
  header_t *h = reqhdr;
  while (h->name) {
    if (strcmp(h->name, name) == 0)
      return h->value;
    h++;
  }
  return NULL;
}

// get all request headers
header_t *request_headers(void) { return reqhdr; }

// Handle escape characters (%xx)
static void uri_unescape(char *uri) {
  char chr = 0;
  char *src = uri;
  char *dst = uri;

  // Skip inital non encoded character
  while (*src && !isspace((int)(*src)) && (*src != '%'))
    src++;

  // Replace encoded characters with corresponding code.
  dst = src;
  while (*src && !isspace((int)(*src))) {
    if (*src == '+')
      chr = ' ';
    else if ((*src == '%') && src[1] && src[2]) {
      src++;
      chr = ((*src & 0x0F) + 9 * (*src > '9')) * 16;
      src++;
      chr += ((*src & 0x0F) + 9 * (*src > '9'));
    } else
      chr = *src;
    *dst++ = chr;
    src++;
  }
  *dst = '\0';
}

// client connection
void respond(int slot, SSL *ssl) {
  int rcvd;

  buf = malloc(BUF_SIZE);
  rcvd = SSL_read(ssl, buf, BUF_SIZE);

  if (rcvd < 0) // receive error
    fprintf(stderr, ("recv() error\n"));
  else if (rcvd == 0) // receive socket closed
    fprintf(stderr, "Client disconnected upexpectedly.\n");
  else // message received
  {
    buf[rcvd] = '\0';

    method = strtok(buf, " \t\r\n");
    uri = strtok(NULL, " \t");
    prot = strtok(NULL, " \t\r\n");

    uri_unescape(uri);

    fprintf(stderr, "\x1b[32m + [%s] %s\x1b[0m\n", method, uri);

    qs = strchr(uri, '?');

    if (qs)
      *qs++ = '\0'; // split URI
    else
      qs = uri - 1; // use an empty string

    header_t *h = reqhdr;
    char *t, *t2;
    while (h < reqhdr + 16) {
      char *key, *val;

      key = strtok(NULL, "\r\n: \t");
      if (!key)
        break;

      val = strtok(NULL, "\r\n");
      while (*val && *val == ' ')
        val++;

      h->name = key;
      h->value = val;
      h++;
      fprintf(stderr, "[H] %s: %s\n", key, val);
      t = val + 1 + strlen(val);
      if (t[1] == '\r' && t[2] == '\n')
        break;
    }
    t = strtok(NULL, "\r\n");
    t2 = request_header("Content-Length"); // and the related header if there is
    payload = t;
    payload_size = t2 ? atol(t2) : (rcvd - (t - buf));

    char *buffer = malloc(BUF_SIZE + 1);
    int out_pipe[2];

    if (pipe(out_pipe) != 0) {
      exit(1);
    }

    dup2(out_pipe[1], STDOUT_FILENO);
    close(out_pipe[1]);

    // call router
    route();

    // tidy up
    fflush(stdout);

    int len = read(out_pipe[0], buffer, BUF_SIZE);

    SSL_write(ssl, buffer, len);
    shutdown(STDOUT_FILENO, SHUT_WR);
    close(STDOUT_FILENO);
    free(buffer);
  }

  free(buf);
}
