CC = g++
CFLAGS = -std=c++11 -Wall -pthread
LDFLAGS = -lsqlite3 -lcrypto -lssl

all: server_dash client_dash

server_dash: server_dash.cpp
	$(CC) $(CFLAGS) -o server_dash server_dash.cpp $(LDFLAGS)

client_dash: client.cpp
	$(CC) $(CFLAGS) -o client_dash client_dash.cpp $(LDFLAGS)

clean:
	rm -f server_dash client_dash auth.db
