## Objectives/Roadmap
- User Authentication (Login and Signup)
- Basic Vote Casting Implementation
- Database Management for Users and Votes
- Monitoring System (checks database updates at regular intervals)
- Merkle Tree Implementation (ensures database integrity)
- Added Multiple Client Handling

## Missing Features
- Merkel Tree Implementation



## System Compilation Commands

- Compile the server executable (outputs "server_bin"):

`g++ -std=c++11 server/server.cpp src/database.cpp -Iinclude -o server_bin -lsqlite3 -lpthread`

- Compile the client executable (outputs "client_bin"):

`g++ -std=c++11 client/client.cpp src/crypto.cpp -Iinclude -o client_bin -lssl -lcrypto`

- Compile the second client (optional)
`g++ -std=c++11 client/client2.cpp src/crypto.cpp -Iinclude -o client2_bin -lssl -lcrypto`

- Compile the monitor executable (outputs "monitor_bin"):

`g++ -std=c++11 monitor/monitor.cpp src/database.cpp -Iinclude -o monitor_bin -lsqlite3`


## Common Isuue & Fix
- REGISTER FAILURE
    Delete the .db file and try to register again, caused by conflicting entries or missing attributes.


## Execution Order
1. Start the server: `./server_bin`
2. Start the monitor: `./monitor_bin`
3. Launch the client: `./client_bin`

## System Dependencies
- SQLite3 development libraries
- OpenSSL development libraries
- POSIX Threads library
