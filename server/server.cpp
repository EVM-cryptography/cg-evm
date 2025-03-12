#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include "database.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>

#define PORT 8080
#define DB_NAME "evote.db"

// A simple helper to split a string by spaces.
std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::stringstream ss(s);
    std::string token;
    while (std::getline(ss, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Processes incoming requests and returns an appropriate response.
std::string processRequest(const std::string &request) {
    std::istringstream iss(request);
    std::string command;
    iss >> command;
    
    if(command == "REGISTER") {
        std::string hashUID, h1;
        iss >> hashUID >> h1;
        if(addUser(DB_NAME, hashUID, h1)) {
            return "REGISTER SUCCESS";
        } else {
            return "REGISTER FAILURE";
        }
    } else if(command == "LOGIN") {
        std::string hashUID, h1;
        iss >> hashUID >> h1;
        if(checkUser(DB_NAME, hashUID, h1)) {
            return "LOGIN SUCCESS";
        } else {
            return "LOGIN FAILURE";
        }
    } else if(command == "CAST_VOTE") {
        std::string encUID, voteHash;
        iss >> encUID >> voteHash;
        if(addVote(DB_NAME, encUID, voteHash)) {
            return "VOTE CAST SUCCESS";
        } else {
            return "VOTE CAST FAILURE";
        }
    }
    return "UNKNOWN COMMAND";
}

int main() {
    // Initialize the SQLite database.
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
        exit(EXIT_FAILURE);
    }
    
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "setsockopt error\n";
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    if(bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "Bind failed\n";
        exit(EXIT_FAILURE);
    }
    
    if(listen(server_fd, 3) < 0) {
        std::cerr << "Listen failed\n";
        exit(EXIT_FAILURE);
    }
    
    std::cout << "Server listening on port " << PORT << "...\n";
    
    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                 (socklen_t*)&addrlen)) < 0) {
            std::cerr << "Accept failed\n";
            continue;
        }
        
        char buffer[1024] = {0};
        int valread = read(new_socket, buffer, 1024);
        if (valread > 0) {
            std::string request(buffer, valread);
            std::string response = processRequest(request);
            send(new_socket, response.c_str(), response.size(), 0);
        }
        close(new_socket);
    }
    
    close(server_fd);
    return 0;
}