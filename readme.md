Objectives/Roadmap
-Login and Signup
-Vote casting(Party Selection Is Missing and Still lacks multi vote checks)
-DB Managemnt of User and Vote
-Monitorring is added to check the updated database on a certain interval.
-Implementation of Merkel Tree to Ensure Integrity of the DB.


Missing Features
-Multi vote check is missing
-Party Selection is Missing
Compilation Commands
# Compile the server executable (outputs "server_bin"):
g++ server/server.cpp src/database.cpp -Iinclude -o server_bin -lsqlite3

# Compile the client executable (outputs "client_bin"):
g++ client/client.cpp src/crypto.cpp -Iinclude -o client_bin -lssl -lcrypto

# Compile the monitor executable (outputs "monitor_bin"):
g++ monitor/monitor.cpp src/database.cpp -Iinclude -o monitor_bin -lsqlite3 -lpthread


Execution Flow:
-srver_bin
-monitor_bin
-client_bin