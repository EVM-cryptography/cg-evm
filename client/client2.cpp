#include <iostream>
#include <string>
#include <sstream>
#include "crypto.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

// Send request to server with simple error handling
std::string sendRequest(const std::string &request) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        std::cerr << "Socket creation error\n";
        return "ERROR";
    }
    
    struct sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    if(inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address\n";
        close(sock);
        return "ERROR";
    }
    
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed\n";
        close(sock);
        return "ERROR";
    }
    
    send(sock, request.c_str(), request.size(), 0);
    
    char buffer[1024] = {0};
    int valread = read(sock, buffer, sizeof(buffer));
    close(sock);
    
    return std::string(buffer, valread);
}

int main() {
    int choice;
    bool loggedIn = false;
    bool hasVoted = false;
    std::string sessionUID, sessionHashUID, sessionH2;
    std::string input;
    
    std::cout << "=== CLIENT 2 ===\n";
    
    while(true) {
        std::cout << "\n--- E-Voting Client Menu ---\n";
        std::cout << "1. Register\n";
        std::cout << "2. Login\n";
        std::cout << "3. Cast Vote\n";
        std::cout << "4. Exit\n";
        std::cout << "Enter your choice: ";
        std::getline(std::cin, input);
        
        try {
            choice = std::stoi(input);
        } catch (...) {
            std::cout << "Invalid input. Please enter a number.\n";
            continue;
        }
        
        switch(choice) {
            case 1: {  // Register
                std::cout << "Enter UID: ";
                std::getline(std::cin, input);
                std::string uid = input;
                
                std::cout << "Enter Password: ";
                std::getline(std::cin, input);
                std::string pwd = input;
                
                std::string hashUID = sha256(uid);
                std::string h1_pwd = sha256(pwd);
                
                std::string response = sendRequest("REGISTER " + hashUID + " " + h1_pwd);
                std::cout << "Server: " << response << std::endl;
                break;
            }
            
            case 2: {  // Login
                std::cout << "Enter UID: ";
                std::getline(std::cin, input);
                std::string uid = input;
                
                std::cout << "Enter Password: ";
                std::getline(std::cin, input);
                std::string pwd = input;
                
                sessionHashUID = sha256(uid);
                std::string h1_pwd = sha256(pwd);
                
                std::string response = sendRequest("LOGIN " + sessionHashUID + " " + h1_pwd);
                std::cout << "Server: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    loggedIn = true;
                    sessionUID = uid;
                    sessionH2 = sha256(pwd + "H2_CONSTANT");
                    hasVoted = (response.find("ALREADY_VOTED") != std::string::npos);
                    
                    if(hasVoted) {
                        std::cout << "You have already voted.\n";
                    }
                }
                break;
            }
            
            case 3: {  // Cast Vote
                if(!loggedIn) {
                    std::cout << "Please login first.\n";
                    break;
                }
                
                if(hasVoted) {
                    std::cout << "You have already voted.\n";
                    break;
                }
                
                std::cout << "\n--- Available Parties ---\n";
                std::cout << "1. BJP\n";
                std::cout << "2. INC\n";
                std::cout << "3. TRS\n";
                std::cout << "Enter your choice (1-3): ";
                
                std::getline(std::cin, input);
                int partyChoice = 0;
                
                try {
                    partyChoice = std::stoi(input);
                    if(partyChoice < 1 || partyChoice > 3) throw std::invalid_argument("");
                } catch (...) {
                    std::cout << "Invalid choice. Vote not cast.\n";
                    break;
                }
                
                std::string vote;
                if(partyChoice == 1) vote = "BJP";
                else if(partyChoice == 2) vote = "INC";
                else vote = "TRS";
                
                std::string voteHash = sha256(vote);
                std::string encUID = aes256_encrypt(sessionUID, sessionH2);
                
                std::string response = sendRequest("CAST_VOTE " + encUID + " " + voteHash + " " + sessionHashUID);
                std::cout << "Server: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    std::cout << "Your vote was successfully recorded!\n";
                    hasVoted = true;
                }
                break;
            }
            
            case 4:  // Exit
                std::cout << "Exiting...\n";
                return 0;
                
            default:
                std::cout << "Invalid choice. Try again.\n";
        }
    }
    
    return 0;
}