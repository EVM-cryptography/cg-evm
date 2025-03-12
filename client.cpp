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

// Function to create and connect a socket to the server
int connect_to_server() {
    int sock = 0;
    struct sockaddr_in server_addr;

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    // Convert IPv4 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        cerr << "Invalid address/Address not supported" << endl;
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Connection to server failed" << endl;
        return -1;
    }

    return sock;
}

// Function for sign-up
void signup(int sock) {
    string username, password;

    cout << "Signup - Enter username: ";
    cin >> username;
    cout << "Signup - Enter password: ";
    cin >> password;

    // Hash the password using SHA-512 twice
    string hashed_password = sha512_hash(password);
    hashed_password = sha512_hash(hashed_password);
    
    // Combine username and hashed password with a "SIGNUP" prefix
    string user_data = "SIGNUP," + username + "," + hashed_password;

    // Send data to server
    send(sock, user_data.c_str(), user_data.length(), 0);
    cout << "Signup credentials sent to server." << endl;
}

// Function for login
void login(int sock) {
    string username, password;

    cout << "Login - Enter username: ";
    cin >> username;
    cout << "Login - Enter password: ";
    cin >> password;

    // Hash the password using SHA-512
    string hashed_password = sha512_hash(password);
hashed_password = sha512_hash(hashed_password);

    // Combine username and hashed password with a "LOGIN" prefix
    string user_data = "LOGIN," + username + "," + hashed_password;

    // Send data to server
    send(sock, user_data.c_str(), user_data.length(), 0);
    
    // Receive response from server
    char buffer[BUFFER_SIZE] = {0};
    int bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
    
    if (bytes_received > 0) {
        cout << "Server response: " << buffer << endl;
    } else {
        cerr << "Failed to receive response from server." << endl;
    }
}

int main() {
    int choice;

    while (true) {
        cout << "\nMenu:\n";
        cout << "1. Signup\n";
        cout << "2. Login\n";
        cout << "3. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        if (choice == 3) {
            cout << "Exiting program." << endl;
            break;
        }

        int sock = connect_to_server();
        if (sock < 0) {
            cerr << "Failed to connect to server. Please try again later." << endl;
            continue;
        }

        switch (choice) {
            case 1:
                signup(sock);
                break;
            case 2:
                login(sock);
                break;
            default:
                cout << "Invalid choice. Please try again." << endl;
                break;
        }

        // Close socket after each operation
        close(sock);
    }

    return 0;
}

