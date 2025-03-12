#include <iostream>
#include <string>
#include <sstream>
#include "database.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define DB_NAME "evote.db"

// Process incoming requests
std::string processRequest(const std::string &request) {
    std::istringstream iss(request);
    std::string command, hashUID, h1, encUID, voteHash;
    
    iss >> command;
    
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
        
        if(addVote(DB_NAME, encUID, voteHash) && markUserAsVoted(DB_NAME, hashUID))
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

int main() {
    if(!initDatabase(DB_NAME)) {
        std::cerr << "Database initialization failed.\n";
        return 1;
    }
    
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    if((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Socket creation error\n";
        return 1;
    }
    
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
       listen(server_fd, 3) < 0) {
        std::cerr << "Socket setup failed\n";
        return 1;
    }
    
    std::cout << "Server listening on port " << PORT << "...\n";
    
    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, 
                                 (socklen_t*)&addrlen)) < 0) {
            continue;
        }
        
        char buffer[1024] = {0};
        int valread = read(new_socket, buffer, 1024);
        if (valread > 0) {
            std::string response = processRequest(std::string(buffer, valread));
            send(new_socket, response.c_str(), response.size(), 0);
        }
        close(new_socket);
    }
}