#include <iostream>
#include <string>
#include <sstream>
#include "crypto.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <termios.h>


#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define MAX_RETRIES 3

// Function to configure terminal for single character input
void enableRawMode() {
    termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Function to restore terminal to normal mode
void disableRawMode() {
    termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= ICANON | ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

// Function to get a single character without echoing
char getch() {
    char buf = 0;
    if (read(STDIN_FILENO, &buf, 1) < 0)
        return 0;
    return buf;
}


// Send request to server with retry mechanism
std::string sendRequest(const std::string &request) {
    for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if(sock < 0) {
            std::cerr << "Socket creation failed, retry " << attempt+1 << "/" << MAX_RETRIES << "\n";
            sleep(1);
            continue;
        }
        
        struct sockaddr_in serv_addr{};  // Zero-initialize
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(SERVER_PORT);
        
        if(inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0 ||
           connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            std::cerr << "Connection failed, retry " << attempt+1 << "/" << MAX_RETRIES << "\n";
            close(sock);
            sleep(1);
            continue;
        }
        
        send(sock, request.c_str(), request.size(), 0);
        
        char buffer[1024] = {0};
        int valread = read(sock, buffer, sizeof(buffer));
        close(sock);
        
        if(valread > 0) return std::string(buffer, valread);
    }
    return "ERROR: Server communication failed";
}

int main() {
    int choice;
    bool loggedIn = false, hasVoted = false;
    std::string sessionUID, sessionHashUID, sessionH2;
    std::string input;
    const char* PARTIES[] = {"BJP", "INC", "TRS"};
    
    while(true) {
        // Display menu
        std::cout << "\n--- E-Voting Client Menu ---\n"
                  << "1. Register\n"
                  << "2. Login\n"
                  << "3. Cast Vote\n"
                  <<"4.verify your vote\n"
                  << "5. Exit\n"
                  << "Enter your choice: ";
        std::getline(std::cin, input);
        
        // Parse choice with simple error handling
        try {
            choice = std::stoi(input);
        } catch (...) {
            std::cout << "Invalid input. Please enter a number.\n";
            continue;
        }
        
        switch(choice) {
            case 1: { // Register
                std::cout << "Enter UID: ";
                std::getline(std::cin, input);
                std::string uid = input;
         std::cout << "Enter Password: " << std::flush;  // Force immediate display

    std::string pwd;
    char ch;
    enableRawMode();
    while ((ch = getch()) != '\n') {  // Read until Enter key is pressed
        if (ch == 127 || ch == 8) {  // Handle backspace (127 or 8)
            if (!pwd.empty()) {
                pwd.pop_back();
                std::cout << "\b \b";
            }
        } else {
            pwd.push_back(ch);
            std::cout << '*';
        }
    }
    disableRawMode();
    std::cout << std::endl;
                
                std::string response = sendRequest("REGISTER " + sha256(uid) + " " + sha256(pwd));
                std::cout << "Server: " << response << std::endl;
                break;
            }
                
            case 2: { // Login
                std::cout << "Enter UID: ";
                std::getline(std::cin, input);
                std::string uid = input;
                
               std::cout << "Enter Password: " << std::flush;  // Force immediate display

    std::string pwd;
    char ch;
    enableRawMode();
    while ((ch = getch()) != '\n') {  // Read until Enter key is pressed
        if (ch == 127 || ch == 8) {  // Handle backspace (127 or 8)
            if (!pwd.empty()) {
                pwd.pop_back();
                std::cout << "\b \b";
            }
        } else {
            pwd.push_back(ch);
            std::cout << '*';
        }
    }
    disableRawMode();
    std::cout << std::endl;
                
                sessionHashUID = sha256(uid);
                std::string response = sendRequest("LOGIN " + sessionHashUID + " " + sha256(pwd));
                std::cout << "Server: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    loggedIn = true;
                    sessionUID = uid;
                    sessionH2 = sha256(pwd + "H2_CONSTANT");
                    hasVoted = (response.find("ALREADY_VOTED") != std::string::npos);
                    
                    if(hasVoted) std::cout << "You have already cast your vote.\n";
                }
                break;
            }
                
            case 3: { // Cast Vote
                if(!loggedIn) {
                    std::cout << "Please login first.\n";
                    break;
                }
                if(hasVoted || sendRequest("CHECK_VOTED " + sessionHashUID) == "ALREADY_VOTED") {
                    std::cout << "You have already voted.\n";
                    hasVoted = true;
                    break;
                }
                
                // Display voting options
                std::cout << "\n--- Available Parties ---\n";
                for(int i = 0; i < 3; i++)
                    std::cout << (i+1) << ". " << PARTIES[i] << std::endl;
                
                // Get and validate vote choice
                std::cout << "Enter your choice (1-3): ";
                std::getline(std::cin, input);
                
                std::string vote;
                try {
                    int partyChoice = std::stoi(input);
                    if(partyChoice < 1 || partyChoice > 3) throw std::invalid_argument("");
                    vote = PARTIES[partyChoice-1];
                } catch (...) {
                    std::cout << "Invalid choice. Vote not cast.\n";
                    break;
                }
                
                // Confirm vote
                std::cout << "You are voting for: " << vote << "\nConfirm? (y/n): ";
                std::getline(std::cin, input);
                if(input != "y" && input != "Y") {
                    std::cout << "Vote canceled.\n";
                    break;
                }
                
                // Send vote to server
                std::string response = sendRequest("CAST_VOTE " + 
                                                  aes256_encrypt(sessionUID, sessionH2) + " " +
                                                  sha256(vote) + " " + 
                                                  sessionHashUID);
                std::cout<<"hash for BJP="<<sha256("BJP")<<std::endl;
                std::cout<<"hash for INC="<<sha256("INC")<<std::endl;

                std::cout << "Server: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    std::cout << "Your vote has been successfully recorded!\n";
                    hasVoted = true;
                }
                break;
            }  
            case 4: // Exit
                std::cout << "Exiting...\n";
                return 0;
                
            default:
                std::cout << "Invalid choice. Try again.\n";
        }
    }
}