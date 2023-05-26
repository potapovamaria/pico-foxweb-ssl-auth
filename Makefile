all: PICOFoxweb

clean:
	@rm -rf *.o
	@rm -rf PICOFoxweb

PICOFoxweb: main.o httpd.o
	gcc -o PICOFoxweb $^ -lssl -lcrypto

main.o: main.c httpd.h
	gcc -c -o main.o main.c -lssl -lcrypto

httpd.o: httpd.c httpd.h
	gcc -c -o httpd.o httpd.c -lssl -lcrypto
