#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <openssl/sha.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

// Function to hash a password using SHA-512
string sha512_hash(const string& password) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)password.c_str(), password.length(), hash);

    string hashed_password;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        char buffer[3];
        sprintf(buffer, "%02x", hash[i]);  // Convert byte to hex string
        hashed_password += buffer;
    }
    return hashed_password;
}

int main() {
    int sock = 0;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        cerr << "Invalid address/Address not supported" << endl;
        return 1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection to server failed" << endl;
        return 1;
    }

    // Get user input
    string username, password;
    cout << "Enter username: ";
    cin >> username;
    cout << "Enter password: ";
    cin >> password;

    // Hash the password using SHA-512
    string hashed_password = sha512_hash(password);
    cout << "Hashed Password (SHA-512): " << hashed_password << endl;

    // Combine username and hashed password
    string user_data = username + "," + hashed_password;

    // Send data to server
    send(sock, user_data.c_str(), user_data.length(), 0);
    cout << "Hashed credentials sent to server." << endl;

    // Close socket
    close(sock);
    return 0;
}
