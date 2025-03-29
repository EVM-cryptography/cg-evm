//// filepath: /home/vk/Documents/vk_evm/git/cg-evm/server/server.cpp
#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <fstream>
#include "database.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/crypto.h"
#include "../include/merkle.h"
#include <nlohmann/json.hpp>

// For convenience
using json = nlohmann::json;
#define PORT 8080
#define DB_NAME "evote.db"
#define BACKLOG 10  // Connection queue size
#define DEBUG_MODE 1  // Set to 0 to disable debug output
MerkleTree voteTree;

// Mutex for thread-safe database operations
std::mutex db_mutex;

// Debug print function
void debugPrint(const std::string& message) {
    if (DEBUG_MODE) {
        std::cout << "DEBUG: " << message << std::endl;
    }
}

// Process client requests
std::string processRequest(const std::string &request) {
    std::istringstream iss(request);
    std::string command, hashUID, h1, encUID, voteHash, publicKey, signature;
    iss >> command;
    
    std::lock_guard<std::mutex> lock(db_mutex);
    
    if(command == "REGISTER") {
        // Read basic parameters first
        iss >> hashUID >> h1;
        
        // NEW: Multi-line reading for PEM public key
        std::string publicKeyLine, pemKey;
        bool foundPublicKey = false;
        while (std::getline(iss, publicKeyLine)) {
            // Trim leading whitespace
            auto pos = publicKeyLine.find_first_not_of(" \t");
            if (pos != std::string::npos) {
                publicKeyLine.erase(0, pos);
            }
            
            if (!publicKeyLine.empty()) {
                foundPublicKey = true;
                pemKey += publicKeyLine + "\n";
                // Exit loop if we find the end of PEM
                if (publicKeyLine.find("-----END PUBLIC KEY-----") != std::string::npos) {
                    break;
                }
            }
        }
        
        if (foundPublicKey) {
            publicKey = pemKey;
            debugPrint("Received public key for registration (first 50 chars): " +
                       publicKey.substr(0, 50) + "...");
            debugPrint("Public key length: " + std::to_string(publicKey.length()));
            
            if (publicKey.find("-----BEGIN PUBLIC KEY-----") == std::string::npos) {
                debugPrint("WARNING: Public key doesn't appear to be in PEM format!");
            }
            
            std::cout << "Registering user with public key: " << hashUID << std::endl;
            return addUserWithKey(DB_NAME, hashUID, h1, publicKey) ?
                   "REGISTER SUCCESS" : "REGISTER FAILURE";
        }
        
        // If no PEM lines found, fall back to adding user without public key
        return addUser(DB_NAME, hashUID, h1) ? "REGISTER SUCCESS" : "REGISTER FAILURE";
    }
    else if(command == "LOGIN") {
        iss >> hashUID >> h1;
        
        if(!checkUser(DB_NAME, hashUID, h1)) 
            return "LOGIN FAILURE";
        
        return hasUserVoted(DB_NAME, hashUID) ? "LOGIN SUCCESS ALREADY_VOTED"
                                              : "LOGIN SUCCESS";
    }
    else if(command == "CAST_VOTE") {
        iss >> encUID >> voteHash >> hashUID;
        
        // Read signature if present
        std::string remainingInput;
        std::getline(iss, remainingInput);
        if (!remainingInput.empty()) {
            // Remove leading spaces
            auto pos = remainingInput.find_first_not_of(" \t");
            if (pos != std::string::npos) {
                remainingInput.erase(0, pos);
            }
            signature = remainingInput;
            std::cout << "Vote received with digital signature." << std::endl;
            debugPrint("Signature received (first 50 chars): " +
                       signature.substr(0, 50) + "...");
            debugPrint("Signature length: " + std::to_string(signature.length()));
        }
        
        if(hasUserVoted(DB_NAME, hashUID))
            return "VOTE CAST FAILURE - ALREADY VOTED";
        
        // Verify signature if provided
        bool signatureValid = false;
        if (!signature.empty()) {
            std::string publicKey = getUserPublicKey(DB_NAME, hashUID);
            debugPrint("Retrieved public key for verification (first 50 chars): " +
                      (publicKey.empty() ? "EMPTY KEY" : publicKey.substr(0, 50) + "..."));
            debugPrint("Public key length: " + std::to_string(publicKey.length()));
            
            if (publicKey.find("-----BEGIN PUBLIC KEY-----") == std::string::npos) {
                debugPrint("WARNING: Retrieved public key doesn't appear to be in PEM format!");
            }
            
            if (!publicKey.empty()) {
                std::string dataToVerify = hashUID + ":" + voteHash;
                debugPrint("Data being verified: " + dataToVerify);
                
                // Save data to file for manual verification if needed
                std::ofstream dataFile("debug_verification_data.txt");
                dataFile << "Public Key:\n" << publicKey << "\n\n";
                dataFile << "Data to verify:\n" << dataToVerify << "\n\n";
                dataFile << "Signature:\n" << signature << "\n";
                dataFile.close();
                
                signatureValid = verifySignature(dataToVerify, signature, publicKey);
                debugPrint("Signature verification result: " +
                           std::string(signatureValid ? "VALID" : "INVALID"));
                
                if (!signatureValid) {
                    std::cout << "ALERT: Invalid signature detected for vote from "
                              << hashUID << std::endl;
                    return "VOTE CAST FAILURE - INVALID SIGNATURE";
                }
                std::cout << "Signature verified successfully for " << hashUID << std::endl;
            } else {
                std::cout << "Warning: No public key found for user "
                          << hashUID << std::endl;
            }
        }
        
        bool voteAdded = signature.empty() 
                         ? addVote(DB_NAME, encUID, voteHash)
                         : addVoteWithSignature(DB_NAME, encUID, voteHash, signature);
        bool statusUpdated = markUserAsVoted(DB_NAME, hashUID);
        
        // Add to Merkle tree with signature
        voteTree.addVote(hashUID, voteHash, signature);
        
        // Get and print the current root hash
        std::string rootHash = voteTree.getRootHash();
        
        std::string combinedHashInput = hashUID + voteHash;
        std::string combinedHash = sha256(combinedHashInput);
        
        std::cout << "----------------------------------------" << std::endl;
        std::cout << "combined hash binding=" << combinedHash << std::endl;
        std::cout << "the leaf node fields UID=" << hashUID << std::endl;
        std::cout << "the leaf node party voted to=" << voteHash << std::endl;
        if (signatureValid) {
            std::cout << "SIGNATURE VERIFIED: YES" << std::endl;
        } else {
            std::cout << "SIGNATURE: " << (signature.empty() ? "NONE" : "UNVERIFIED") << std::endl;
        }
        std::cout << "MERKLE TREE ROOT HASH=" << rootHash << std::endl;
        std::cout << "TOTAL VOTES IN TREE=" << voteTree.getLeafCount() << std::endl;
        
        // Print the entire tree structure
        voteTree.printTree();
        
        std::cout << "----------------------------------------" << std::endl;
        
        if (voteAdded && statusUpdated)
            return "VOTE CAST SUCCESS";
        else
            return "VOTE CAST FAILURE";
    }
    else if(command == "GET_VERIFICATION_DATA") {
        // Return serialized Merkle tree
        return voteTree.serializeToJson();
    }
    else if(command == "CHECK_VOTED") {
        iss >> hashUID;
        return hasUserVoted(DB_NAME, hashUID) ? "ALREADY_VOTED" : "NOT_VOTED";
    }
    else if(command == "FETCH_NODE") {
        iss >> hashUID;
        
        // Check if the user has voted
        if(!hasUserVoted(DB_NAME, hashUID))
            return "FETCH_NODE FAILURE - NO VOTE FOUND";
        
        // Enhanced response with full Merkle proof and signature information
        MerkleTree::Node* node = voteTree.findNodeByUserHash(hashUID);
        if (!node) {
            return "FETCH_NODE FAILURE - NODE NOT FOUND IN MERKLE TREE";
        }
        
        json response;
        response["status"] = "SUCCESS";
        response["userHash"] = node->userHash;
        response["voteHash"] = node->voteHash;
        response["nodeHash"] = node->hash;
        response["signature"] = node->signature;
        response["rootHash"] = voteTree.getRootHash();
        response["merkleProof"] = voteTree.getMerkleProof(hashUID);
        response["totalNodes"] = voteTree.getLeafCount();
        
        // Add signature verification status if available
        if (!node->signature.empty()) {
            std::string publicKey = getUserPublicKey(DB_NAME, hashUID);
            if (!publicKey.empty()) {
                std::string dataToVerify = hashUID + ":" + node->voteHash;
                bool signatureValid = verifySignature(dataToVerify, node->signature, publicKey);
                response["signatureValid"] = signatureValid;
            }
        }
        
        return "FETCH_NODE SUCCESS\n" + response.dump(2);
    }
    else if(command == "VERIFY_VOTE") {
        iss >> hashUID;
        
        // Check if the user has voted
        if(!hasUserVoted(DB_NAME, hashUID))
            return "VERIFY_VOTE FAILURE - NO VOTE FOUND";
        
        MerkleTree::Node* node = voteTree.findNodeByUserHash(hashUID);
        if (!node) {
            return "VERIFY_VOTE FAILURE - NODE NOT FOUND";
        }
        
        std::string proof = voteTree.getMerkleProof(hashUID);
        std::string rootHash = voteTree.getRootHash();
        
        json response;
        response["status"] = "SUCCESS";
        response["userHash"] = node->userHash;
        response["voteHash"] = node->voteHash;
        response["signature"] = node->signature;
        response["leafHash"] = node->hash;
        response["proof"] = proof;
        response["rootHash"] = rootHash;
        response["treeSize"] = voteTree.getLeafCount();
        
        // Add signature verification if available
        if (!node->signature.empty()) {
            std::string publicKey = getUserPublicKey(DB_NAME, hashUID);
            if (!publicKey.empty()) {
                std::string dataToVerify = hashUID + ":" + node->voteHash;
                bool signatureValid = verifySignature(dataToVerify, node->signature, publicKey);
                response["signatureValid"] = signatureValid;
            }
        }
        
        return "VERIFY_VOTE SUCCESS\n" + response.dump(2);
    }
    
    return "UNKNOWN COMMAND";
}

// Thread function to handle a single client
void handleClient(int client_socket) {
    char buffer[4096] = {0};
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
    
    // Set socket options
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
    std::cout << "Digital signatures are enabled for vote verification.\n";
    
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