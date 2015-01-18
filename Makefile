all: server client

server:
	gcc -g -o server server.c

client:
	gcc -g -o client client.c

clean:
	rm -f server.o server client.o client
