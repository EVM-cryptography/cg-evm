#include <iostream>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <iomanip>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#define PORT 8080
#define BUFFER_SIZE 1024
#define SERVER_IP "127.0.0.1"

// Function to compute SHA-512 hash
std::string sha512(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, input.c_str(), input.length());
    SHA512_Final(hash, &sha512);
    
    std::stringstream ss;
    for(int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Function to send command to server and get response
std::string sendCommand(const std::string& command) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    
    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Socket creation error" << std::endl;
        return "ERROR";
    }
    
    // Set up server address
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    // Convert IPv4 address from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported" << std::endl;
        close(sock);
        return "ERROR";
    }
    
    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Connection failed" << std::endl;
        close(sock);
        return "ERROR";
    }
    
    // Send command to server
    send(sock, command.c_str(), command.length(), 0);
    
    // Receive response from server
    int valread = read(sock, buffer, BUFFER_SIZE);
    std::string response(buffer);
    
    // Close socket
    close(sock);
    
    return response;
}

// Function to register a new user
bool registerUser() {
    std::string username, password;
    
    std::cout << "=== User Registration ===" << std::endl;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    
    // Hash username with SHA-512
    std::string username_hash = sha512(username);
    
    // Double hash password with SHA-512
    std::string password_hash = sha512(password);
    std::string password_double_hash = sha512(password_hash);
    
    // Send registration command to server
    std::string command = "REGISTER " + username_hash + " " + password_double_hash;
    std::string response = sendCommand(command);
    
    if (response == "REGISTER_SUCCESS") {
        std::cout << "Registration successful!" << std::endl;
        return true;
    } else {
        std::cout << "Registration failed. User may already exist." << std::endl;
        return false;
    }
}

// Function to login
bool login() {
    std::string username, password;
    
    std::cout << "=== User Login ===" << std::endl;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    
    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    
    // Hash username with SHA-512
    std::string username_hash = sha512(username);
    
    // Double hash password with SHA-512
    std::string password_hash = sha512(password);
    std::string password_double_hash = sha512(password_hash);
    
    // Send login command to server
    std::string command = "LOGIN " + username_hash + " " + password_double_hash;
    std::string response = sendCommand(command);
    
    if (response == "LOGIN_SUCCESS") {
        std::cout << "Login successful!" << std::endl;
        return true;
    } else {
        std::cout << "Login failed. Invalid username or password." << std::endl;
        return false;
    }
}

int main() {
    std::cout << "Welcome to Secure Authentication System" << std::endl;
    
    bool running = true;
    while (running) {
        std::cout << "\nChoose an option:" << std::endl;
        std::cout << "1. Register" << std::endl;
        std::cout << "2. Login" << std::endl;
        std::cout << "3. Exit" << std::endl;
        std::cout << "Option: ";
        
        std::string option;
        std::getline(std::cin, option);
        
        if (option == "1") {
            registerUser();
        } 
        else if (option == "2") {
            if (login()) {
                std::cout << "You are now logged in!" << std::endl;
                // Here you could add additional functionality for logged-in users
            }
        } 
        else if (option == "3") {
            std::cout << "Exiting..." << std::endl;
            running = false;
        } 
        else {
            std::cout << "Invalid option. Please try again." << std::endl;
        }
    }
    
    return 0;
}
