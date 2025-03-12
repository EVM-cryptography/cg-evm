#include <iostream>
#include <string>
#include <sstream>
#include "crypto.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

// Send request to server and get response
std::string sendRequest(const std::string &request) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) return "ERROR";
    
    sockaddr_in serv_addr{};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    if(inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0 ||
       connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return "ERROR";
    }
    
    send(sock, request.c_str(), request.size(), 0);
    
    char buffer[1024] = {0};
    int valread = read(sock, buffer, 1024);
    close(sock);
    
    return std::string(buffer, valread);
}

int main() {
    int choice;
    bool loggedIn = false;
    bool hasVoted = false;
    std::string sessionUID, sessionHashUID, sessionH2;
    std::string input, uid, pwd, response, vote;
    
    const char* PARTIES[] = {"BJP", "INC", "TRS"};
    
    while(true) {
        std::cout << "\n--- E-Voting Client Menu ---\n"
                  << "1. Register\n"
                  << "2. Login\n"
                  << "3. Cast Vote\n"
                  << "4. Exit\n"
                  << "Enter your choice: ";
        std::getline(std::cin, input);
        
        try {
            choice = std::stoi(input);
        } catch (...) {
            std::cout << "Invalid input. Please enter a number.\n";
            continue;
        }
        
        // Declaration moved outside the switch to avoid scope issues
        int partyChoice = 0;
        
        switch(choice) {
            case 1: // Register
                std::cout << "Enter UID: ";
                std::getline(std::cin, uid);
                std::cout << "Enter Password: ";
                std::getline(std::cin, pwd);
                
                response = sendRequest("REGISTER " + sha256(uid) + " " + sha256(pwd));
                std::cout << "Server response: " << response << std::endl;
                break;
                
            case 2: // Login
                std::cout << "Enter UID: ";
                std::getline(std::cin, uid);
                std::cout << "Enter Password: ";
                std::getline(std::cin, pwd);
                
                sessionHashUID = sha256(uid);
                response = sendRequest("LOGIN " + sessionHashUID + " " + sha256(pwd));
                std::cout << "Server response: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    loggedIn = true;
                    sessionUID = uid;
                    sessionH2 = sha256(pwd + "H2_CONSTANT");
                    hasVoted = (response.find("ALREADY_VOTED") != std::string::npos);
                    
                    if(hasVoted)
                        std::cout << "You have already cast your vote.\n";
                }
                break;
                
            case 3: // Cast Vote
                if(!loggedIn) {
                    std::cout << "Please login first.\n";
                    break;
                }
                if(hasVoted || sendRequest("CHECK_VOTED " + sessionHashUID) == "ALREADY_VOTED") {
                    std::cout << "You have already voted.\n";
                    hasVoted = true;
                    break;
                }
                
                // Party selection menu
                std::cout << "\n--- Available Parties ---\n";
                for(int i = 0; i < 3; i++)
                    std::cout << (i+1) << ". " << PARTIES[i] << std::endl;
                std::cout << "Enter your choice (1-3): ";
                
                std::getline(std::cin, input);
                
                try {
                    partyChoice = std::stoi(input);
                    if(partyChoice < 1 || partyChoice > 3) throw std::invalid_argument("");
                    vote = PARTIES[partyChoice-1];
                } catch (...) {
                    std::cout << "Invalid choice. Vote not cast.\n";
                    break;
                }
                
                std::cout << "You are voting for: " << vote << "\nConfirm? (y/n): ";
                std::getline(std::cin, input);
                if(input != "y" && input != "Y") {
                    std::cout << "Vote canceled.\n";
                    break;
                }
                
                response = sendRequest("CAST_VOTE " + 
                                       aes256_encrypt(sessionUID, sessionH2) + " " +
                                       sha256(vote) + " " + 
                                       sessionHashUID);
                
                std::cout << "Server response: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    std::cout << "Your vote has been successfully recorded!\n";
                    hasVoted = true;
                }
                break;
                
            case 4: // Exit
                std::cout << "Exiting...\n";
                return 0;
                
            default:
                std::cout << "Invalid choice. Try again.\n";
        }
    }
}