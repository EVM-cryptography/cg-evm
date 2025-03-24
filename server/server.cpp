#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include "database.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "crypto.h"

#define PORT 8080
#define DB_NAME "evote.db"
#define BACKLOG 10  // Connection queue size

// Mutex for thread-safe database operations
std::mutex db_mutex;

// Process client requests
std::string processRequest(const std::string &request) {
    std::istringstream iss(request);
    std::string command, hashUID, h1, encUID, voteHash;
    iss >> command;
    
    std::lock_guard<std::mutex> lock(db_mutex);
    
    if(command == "REGISTER") {
        iss >> hashUID >> h1;
        return addUser(DB_NAME, hashUID, h1) ? "REGISTER SUCCESS" : "REGISTER FAILURE";
    } 
    else if(command == "LOGIN") {
        iss >> hashUID >> h1;
        
        if(!checkUser(DB_NAME, hashUID, h1)) 
            return "LOGIN FAILURE";
        
        return hasUserVoted(DB_NAME, hashUID) ? "LOGIN SUCCESS ALREADY_VOTED" : "LOGIN SUCCESS";
    } 
    else if(command == "CAST_VOTE") {
        iss >> encUID >> voteHash >> hashUID;
        
        if(hasUserVoted(DB_NAME, hashUID))
            return "VOTE CAST FAILURE - ALREADY VOTED";
        
        bool voteAdded = addVote(DB_NAME, encUID, voteHash);
        bool statusUpdated = markUserAsVoted(DB_NAME, hashUID);
        std::string combinedHashInput = hashUID + voteHash;
        std::string combinedHash = sha256(combinedHashInput);
        std::cout<<"combined hash binding="<<combinedHash<<std::endl;
        if(voteAdded && statusUpdated) 
            return "VOTE CAST SUCCESS";
        else
            return "VOTE CAST FAILURE";
    } 
    else if(command == "CHECK_VOTED") {
        iss >> hashUID;
        return hasUserVoted(DB_NAME, hashUID) ? "ALREADY_VOTED" : "NOT_VOTED";
    }
    
    return "UNKNOWN COMMAND";
}

// Thread function to handle a single client
void handleClient(int client_socket) {
    char buffer[1024] = {0};
    int valread = read(client_socket, buffer, sizeof(buffer));
    
    if (valread > 0) {
        std::string request(buffer, valread);
        std::string response = processRequest(request);
        send(client_socket, response.c_str(), response.size(), 0);
    }
    
    close(client_socket);
}

int main() {
    // Initialize database once at startup
    {
        std::lock_guard<std::mutex> lock(db_mutex);
        if(!initDatabase(DB_NAME)) {
            std::cerr << "Database initialization failed\n";
            return 1;
        }
    }
    
    // Create and configure socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        std::cerr << "Socket creation failed\n";
        return 1;
    }
    
    // Set socket options for reuse
    int opt = 1;
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "setsockopt failed\n";
        close(server_fd);
        return 1;
    }
    
    // Configure address
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind and listen
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
       listen(server_fd, BACKLOG) < 0) {
        std::cerr << "Bind or listen failed\n";
        close(server_fd);
        return 1;
    }
    
    std::cout << "Multi-threaded server listening on port " << PORT << "...\n";
    
    // Main accept loop
    while (true) {
        sockaddr_in client_addr{};
        socklen_t addrlen = sizeof(client_addr);
        
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (client_socket < 0) {
            std::cerr << "Accept failed\n";
            continue;
        }
        
        // Handle client in separate thread
        std::thread(handleClient, client_socket).detach();
    }
}