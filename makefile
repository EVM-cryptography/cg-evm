CC = g++
CFLAGS = -std=c++11 -Wall -pthread
LDFLAGS = -lsqlite3 -lcrypto -lssl

all: server client

server: server.cpp
	$(CC) $(CFLAGS) -o server server.cpp $(LDFLAGS)

client: client.cpp
	$(CC) $(CFLAGS) -o client client.cpp $(LDFLAGS)

clean:
	rm -f server client auth.db
