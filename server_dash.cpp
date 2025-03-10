#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>

#define PORT 8080
#define BUFFER_SIZE 1024

// SQLite database handler
sqlite3* db;
std::mutex db_mutex;

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

// Initialize database
bool initDatabase() {
    std::lock_guard<std::mutex> lock(db_mutex);
    int rc = sqlite3_open("auth.db", &db);
    
    if (rc) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    // Create users table if it doesn't exist
    const char* sql = "CREATE TABLE IF NOT EXISTS users ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "username_hash TEXT NOT NULL UNIQUE,"
                      "password_double_hash TEXT NOT NULL);";
                      
    char* errMsg = nullptr;
    rc = sqlite3_exec(db, sql, nullptr, nullptr, &errMsg);
    
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    
    std::cout << "Database initialized successfully" << std::endl;
    return true;
}

// Register a new user
bool registerUser(const std::string& username_hash, const std::string& password_double_hash) {
    std::lock_guard<std::mutex> lock(db_mutex);
    // Prepare SQL statement
    std::string sql = "INSERT INTO users (username_hash, password_double_hash) VALUES (?, ?);";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    // Bind parameters
    sqlite3_bind_text(stmt, 1, username_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_double_hash.c_str(), -1, SQLITE_STATIC);
    
    // Execute statement
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            std::cerr << "User already exists" << std::endl;
        } else {
            std::cerr << "Failed to register user: " << sqlite3_errmsg(db) << std::endl;
        }
        return false;
    }
    
    std::cout << "User registered successfully" << std::endl;
    return true;
}

// Authenticate a user
bool authenticateUser(const std::string& username_hash, const std::string& password_double_hash) {
    std::lock_guard<std::mutex> lock(db_mutex);
    // Prepare SQL statement
    std::string sql = "SELECT * FROM users WHERE username_hash = ? AND password_double_hash = ?;";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
    
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    // Bind parameters
    sqlite3_bind_text(stmt, 1, username_hash.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_double_hash.c_str(), -1, SQLITE_STATIC);
    
    // Execute statement
    rc = sqlite3_step(stmt);
    
    // Check if we found a matching user
    bool authenticated = (rc == SQLITE_ROW);
    
    sqlite3_finalize(stmt);
    
    return authenticated;
}

// Process client commands
std::string processCommand(const std::string& command) {
    std::istringstream iss(command);
    std::string action;
    iss >> action;
    
    if (action == "REGISTER") {
        std::string username_hash, password_double_hash;
        iss >> username_hash >> password_double_hash;
        
        if (registerUser(username_hash, password_double_hash)) {
            return "REGISTER_SUCCESS";
        } else {
            return "REGISTER_FAILURE";
        }
    } 
    else if (action == "LOGIN") {
        std::string username_hash, password_double_hash;
        iss >> username_hash >> password_double_hash;
        
        if (authenticateUser(username_hash, password_double_hash)) {
            return "LOGIN_SUCCESS";
        } else {
            return "LOGIN_FAILURE";
        }
    }
    else {
        return "UNKNOWN_COMMAND";
    }
}

// Handle client connection in a separate thread
void handleClient(int client_socket) {
    char buffer[BUFFER_SIZE] = {0};
    
    // Receive command from client
    int valread = read(client_socket, buffer, BUFFER_SIZE);
    if (valread <= 0) {
        close(client_socket);
        return;
    }
    
    std::string command(buffer);
    std::cout << "Received command: " << command << std::endl;
    
    // Process command and send response
    std::string response = processCommand(command);
    send(client_socket, response.c_str(), response.length(), 0);
    
    // Close client socket
    close(client_socket);
}

int main() {
    // Initialize database
    if (!initDatabase()) {
        return 1;
    }
    
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        return 1;
    }
    
    // Configure address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind socket to address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        return 1;
    }
    
    // Listen for incoming connections
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        return 1;
    }
    
    std::cout << "Server started. Listening on port " << PORT << "..." << std::endl;
    
    std::vector<std::thread> threads;
    
    while (true) {
        // Accept incoming connection
        int client_socket;
        if ((client_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept failed");
            continue;
        }
        
        // Get client IP address
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(address.sin_addr), client_ip, INET_ADDRSTRLEN);
        std::cout << "New connection from " << client_ip << std::endl;
        
        // Handle client in a separate thread
        threads.push_back(std::thread(handleClient, client_socket));
        
        // Detach thread to allow it to run independently
        threads.back().detach();
    }
    
    // Close server socket
    close(server_fd);
    
    // Close database connection
    sqlite3_close(db);
    
    return 0;
}
