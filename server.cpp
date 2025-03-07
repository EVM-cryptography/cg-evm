#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <pthread.h>
#include <libpq-fe.h>

#define PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

// Function to insert data into the PostgreSQL database
void insert_into_db(const string& username, const string& hashed_password) {
    PGconn* conn = PQconnectdb("dbname=voters user=postgres password='evm' hostaddr=127.0.0.1 port=5432");

    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "Database connection failed: " << PQerrorMessage(conn) << endl;
        PQfinish(conn);
        return;
    }

    string query = "INSERT INTO voters (username, hashed_password) VALUES ('" + username + "', '" + hashed_password + "');";
    PGresult* res = PQexec(conn, query.c_str());

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        cerr << "Insert failed: " << PQerrorMessage(conn) << endl;
    } else {
        cout << "Data inserted successfully: " << username << endl;
    }

    PQclear(res);
    PQfinish(conn);
}

// Function to handle client connections
void* handle_client(void* socket_desc) {
    int new_socket = *(int*)socket_desc;
    char buffer[BUFFER_SIZE] = {0};

    read(new_socket, buffer, BUFFER_SIZE);
    cout << "Received: " << buffer << endl;

    // Parse received data (format: "username,hashed_password")
    string data(buffer);
    size_t comma_pos = data.find(",");
    if (comma_pos != string::npos) {
        string username = data.substr(0, comma_pos);
        string hashed_password = data.substr(comma_pos + 1);
        insert_into_db(username, hashed_password);
    } else {
        cerr << "Invalid data format" << endl;
    }

    close(new_socket);
    delete (int*)socket_desc;
    pthread_exit(NULL);
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        cerr << "Socket creation failed" << endl;
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        cerr << "Bind failed" << endl;
        return 1;
    }

    if (listen(server_fd, 30) < 0) {
        cerr << "Listen failed" << endl;
        return 1;
    }

    cout << "Server listening on port " << PORT << endl;

    while (true) {
        new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen);
        if (new_socket < 0) {
            cerr << "Accept failed" << endl;
            continue;
        }

        pthread_t client_thread;
        int* new_sock = new int(new_socket);
        if (pthread_create(&client_thread, NULL, handle_client, (void*)new_sock) != 0) {
            cerr << "Thread creation failed" << endl;
            close(new_socket);
            delete new_sock;
        }
        pthread_detach(client_thread);
    }

    close(server_fd);
    return 0;
}
