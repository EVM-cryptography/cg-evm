#include <iostream>
#include <string>
#include <sstream>
#include "crypto.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"

// A helper function to connect to the server, send the request, and receive a response.
std::string sendRequest(const std::string &request) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        std::cerr << "Socket creation error\n";
        return "ERROR";
    }
    
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    if(inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported\n";
        return "ERROR";
    }
    
    if(connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed\n";
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
    std::string sessionUID;
    std::string sessionH2; // H2 is used as the AES256 key (derived from the password)
    std::string input;
    
    while(true) {
        std::cout << "\n--- E-Voting Client Menu ---\n";
        std::cout << "1. Register\n";
        std::cout << "2. Login\n";
        std::cout << "3. Cast Vote\n";
        std::cout << "4. Exit\n";
        std::cout << "Enter your choice: ";
        std::getline(std::cin, input);
        choice = std::stoi(input);
        
        if(choice == 1) {
            // Registration Process
            std::string uid, pwd;
            std::cout << "Enter UID: ";
            std::getline(std::cin, uid);
            std::cout << "Enter Password: ";
            std::getline(std::cin, pwd);
            
            // Compute a hash of UID and generate H1 and H2 from the password.
            std::string hashUID = sha256(uid);
            std::string H1 = sha256(pwd);
            // Differentiate H2 (here by appending a constant).
            std::string H2 = sha256(pwd + "H2_CONSTANT");
            
            // Prepare registration request: "REGISTER <hashUID> <H1>"
            std::stringstream ss;
            ss << "REGISTER " << hashUID << " " << H1;
            std::string response = sendRequest(ss.str());
            std::cout << "Server response: " << response << std::endl;
        } else if(choice == 2) {
            // Login Process
            std::string uid, pwd;
            std::cout << "Enter UID: ";
            std::getline(std::cin, uid);
            std::cout << "Enter Password: ";
            std::getline(std::cin, pwd);
            
            std::string hashUID = sha256(uid);
            std::string H1 = sha256(pwd);
            std::string H2 = sha256(pwd + "H2_CONSTANT");
            
            std::stringstream ss;
            ss << "LOGIN " << hashUID << " " << H1;
            std::string response = sendRequest(ss.str());
            std::cout << "Server response: " << response << std::endl;
            if(response.find("SUCCESS") != std::string::npos) {
                loggedIn = true;
                sessionUID = uid;
                sessionH2 = H2;
            }
        } else if(choice == 3) {
            // Cast Vote (requires a successful login)
            if(!loggedIn) {
                std::cout << "Please login first.\n";
                continue;
            }
            std::string vote;
            std::cout << "Enter your vote (Party Name): ";
            std::getline(std::cin, vote);
            
            std::string voteHash = sha256(vote);
            // Encrypt UID using H2 as the key.
            std::string encUID = aes256_encrypt(sessionUID, sessionH2);
            std::stringstream ss;
            ss << "CAST_VOTE " << encUID << " " << voteHash;
            std::string response = sendRequest(ss.str());
            std::cout << "Server response: " << response << std::endl;
        } else if(choice == 4) {
            std::cout << "Exiting...\n";
            break;
        } else {
            std::cout << "Invalid choice. Try again.\n";
        }
    }
    
    return 0;
}