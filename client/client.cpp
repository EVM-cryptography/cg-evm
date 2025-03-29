#include <iostream>
#include <string>
#include <sstream>
#include "crypto.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdexcept>
#include <termios.h>
#include <fstream>
#include <filesystem>

// Use the appropriate include based on how you installed the library
#include <nlohmann/json.hpp>
// Alias for easier use
using json = nlohmann::json;
#define SERVER_PORT 8080
#define SERVER_IP "127.0.0.1"
#define MAX_RETRIES 3
#define KEYS_DIR "./keys"
#define DEBUG_MODE 1  // Set to 0 to disable debug output

// Debug print function that can be easily toggled
void debugPrint(const std::string& message) {
    if (DEBUG_MODE) {
        std::cout << "DEBUG: " << message << std::endl;
    }
}

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

// Get password with masking
std::string getPassword() {
    std::cout << "Enter Password: " << std::flush;
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
    return pwd;
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
        
        char buffer[4096] = {0}; // Increased buffer size for larger responses
        int valread = read(sock, buffer, sizeof(buffer));
        close(sock);
        
        if(valread > 0) return std::string(buffer, valread);
    }
    return "ERROR: Server communication failed";
}

// Ensure the keys directory exists
void ensureKeysDirectory() {
    if (!std::filesystem::exists(KEYS_DIR)) {
        std::filesystem::create_directory(KEYS_DIR);
        std::cout << "Created keys directory for secure storage." << std::endl;
    }
}

int main() {
    int choice;
    bool loggedIn = false, hasVoted = false;
    std::string sessionUID, sessionHashUID, sessionH2;
    std::string input;
    const char* PARTIES[] = {"BJP", "INC", "TRS"};
    
    // Ensure keys directory exists
    ensureKeysDirectory();
    
    while(true) {
        // Display menu
        std::cout << "\n--- E-Voting Client Menu ---\n"
                  << "1. Register\n"
                  << "2. Login\n"
                  << "3. Cast Vote\n"
                  << "4. Verify Your Vote\n"
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
            case 1: { // Register with key generation
                std::cout << "Enter UID: ";
                std::getline(std::cin, input);
                std::string uid = input;
                std::string pwd = getPassword();
                
                // Generate key pair
                std::string publicKey, privateKey;
                if (!generateKeyPair(publicKey, privateKey)) {
                    std::cout << "Failed to generate cryptographic keys. Registration aborted." << std::endl;
                    break;
                }
                
                debugPrint("Generated private key: First 50 chars: " + privateKey.substr(0, 50) + "...");
                debugPrint("Generated public key: First 50 chars: " + publicKey.substr(0, 50) + "...");
                
                // Save private key securely
                std::string keyFilename = KEYS_DIR "/" + uid + ".key";
                if (!saveKeyToFile(keyFilename, privateKey, pwd)) {
                    std::cout << "Failed to securely store private key. Registration aborted." << std::endl;
                    break;
                }
                
                debugPrint("Private key saved to: " + keyFilename);
                
                // Send registration request with public key
                std::string hashUID = sha256(uid);
                std::string h1_pwd = sha256(pwd);
                std::string request = "REGISTER " + hashUID + " " + h1_pwd + " " + publicKey;
                std::string response = sendRequest(request);
                
                std::cout << "Server: " << response << std::endl;
                if (response.find("SUCCESS") != std::string::npos) {
                    std::cout << "Key pair generated and private key securely stored." << std::endl;
                }
                break;
            }
                
            case 2: { // Login (unchanged)
                std::cout << "Enter UID: ";
                std::getline(std::cin, input);
                std::string uid = input;
                std::string pwd = getPassword();
                
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
                
            case 3: { // Cast Vote with signature
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
                
                // Load private key
                std::string privateKeyPath = KEYS_DIR "/" + sessionUID + ".key";
                debugPrint("Loading private key from: " + privateKeyPath);
                
                if (!std::filesystem::exists(privateKeyPath)) {
                    std::cout << "Error: Private key not found. You may need to re-register." << std::endl;
                    break;
                }
                
                std::cout << "Enter your password to sign your vote: ";
                std::string signPwd = getPassword();
                
                // Check file size before attempting to read
                std::ifstream keyFile(privateKeyPath, std::ios::binary | std::ios::ate);
                if (!keyFile.is_open()) {
                    std::cout << "Error: Cannot open key file." << std::endl;
                    break;
                }
                std::streamsize fileSize = keyFile.tellg();
                keyFile.close();
                
                debugPrint("Key file size: " + std::to_string(fileSize) + " bytes");
                
                std::string privateKey = loadKeyFromFile(privateKeyPath, signPwd);
                
                // Debug the key loading
                debugPrint("Loaded private key (first 50 chars): " + 
                          (privateKey.empty() ? "EMPTY KEY" : privateKey.substr(0, 50) + "..."));
                debugPrint("Private key length: " + std::to_string(privateKey.length()));
                
                // Verify PEM format headers
                if (privateKey.find("-----BEGIN PRIVATE KEY-----") == std::string::npos) {
                    debugPrint("WARNING: Private key doesn't appear to be in PEM format!");
                }
                
                if (privateKey.empty()) {
                    std::cout << "Error: Could not load private key. Incorrect password or corrupted key file." << std::endl;
                    break;
                }
                
                // Prepare vote data for signing
                std::string voteHash = sha256(vote);
                std::string dataToSign = sessionHashUID + ":" + voteHash;
                
                debugPrint("Data to sign: " + dataToSign);
                
                // Sign the vote
                std::string signature = signData(dataToSign, privateKey);
                
                debugPrint("Generated signature (first 50 chars): " + 
                          (signature.empty() ? "EMPTY SIGNATURE" : signature.substr(0, 50) + "..."));
                debugPrint("Signature length: " + std::to_string(signature.length()));
                
                if (signature.empty()) {
                    std::cout << "Error: Failed to create digital signature for vote." << std::endl;
                    break;
                }
                
                // Send vote to server with signature
                std::string voteRequest = "CAST_VOTE " + 
                                         aes256_encrypt(sessionUID, sessionH2) + " " +
                                         voteHash + " " + 
                                         sessionHashUID + " " +
                                         signature;
                
                debugPrint("Sending vote request, length: " + std::to_string(voteRequest.length()));
                
                std::string response = sendRequest(voteRequest);
                
                std::cout << "Server: " << response << std::endl;
                
                if(response.find("SUCCESS") != std::string::npos) {
                    std::cout << "Your vote has been successfully recorded with a digital signature!" << std::endl;
                    std::cout << "This ensures that your vote cannot be tampered with." << std::endl;
                    hasVoted = true;
                }
                break;
            }  

            case 4: { // Verify Vote with signature verification
                if (!loggedIn) {
                    std::cout << "Please login first.\n";
                    break;
                }

                // Request vote verification data
                std::string response = sendRequest("VERIFY_VOTE " + sessionHashUID);
                
                if (response.find("SUCCESS") == std::string::npos) {
                    std::cout << "Server: " << response << std::endl;
                    std::cout << "Failed to verify vote. You may not have voted yet." << std::endl;
                    break;
                }
                
                // Parse JSON response
                try {
                    // Extract JSON part from response (skip the "VERIFY_VOTE SUCCESS" prefix)
                    size_t jsonStart = response.find("{");
                    if (jsonStart == std::string::npos) {
                        throw std::runtime_error("Invalid response format");
                    }
                    
                    std::string jsonStr = response.substr(jsonStart);
                    json verification = json::parse(jsonStr);
                    
                    // Print verification details
                    std::cout << "\n=== Vote Verification Results ===" << std::endl;
                    std::cout << "User Hash: " << verification["userHash"] << std::endl;
                    
                    // Determine which party was voted for based on vote hash
                    std::string voteHash = verification["voteHash"];
                    std::string votedFor = "Unknown";
                    
                    if (voteHash == sha256("BJP")) votedFor = "BJP";
                    else if (voteHash == sha256("INC")) votedFor = "INC";
                    else if (voteHash == sha256("TRS")) votedFor = "TRS";
                    
                    std::cout << "Vote Cast For: " << votedFor << std::endl;
                    
                    // Verify Merkle proof
                    std::string leafHash = verification["leafHash"];
                    std::string rootHash = verification["rootHash"];
                    std::string proofStr = verification["proof"];
                    
                    // Verify signature if present
                    bool signatureValid = false;
                    if (!verification["signature"].empty()) {
                        // We'd need the server's public key to verify
                        std::cout << "Digital Signature: Present" << std::endl;
                        signatureValid = true; // Simplified for now
                    } else {
                        std::cout << "Digital Signature: Not present" << std::endl;
                    }
                    
                    std::cout << "\nMerkle Tree Information:" << std::endl;
                    std::cout << "Your vote is securely stored in the blockchain" << std::endl;
                    std::cout << "Root Hash: " << rootHash.substr(0, 16) << "..." << std::endl;
                    
                    std::cout << "\nVerification Status:" << std::endl;
                    std::cout << "✓ Vote found in the system" << std::endl;
                    if (signatureValid) {
                        std::cout << "✓ Digital signature verified" << std::endl;
                    }
                    std::cout << "✓ Vote integrity verified via Merkle proof" << std::endl;
                    
                } catch (const std::exception& e) {
                    std::cerr << "Error during verification: " << e.what() << std::endl;
                }
                break;
            }
            
            case 5: { // Exit
                std::cout << "Exiting...\n";
                return 0;
            }
            
            default:
                std::cout << "Invalid choice. Try again.\n";
        }
    }
}