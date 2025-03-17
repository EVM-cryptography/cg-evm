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

//adding to database
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
        cout << "Signup successful for user: " << username << endl;
    }

    PQclear(res);
    PQfinish(conn);
}
//login query 
bool verify_login(const string& username, const string& hashed_password) {
    PGconn* conn = PQconnectdb("dbname=voters user=postgres password='evm' hostaddr=127.0.0.1 port=5432");

    if (PQstatus(conn) != CONNECTION_OK) {
        cerr << "Database connection failed: " << PQerrorMessage(conn) << endl;
        PQfinish(conn);
        return false;
    }

    string query = "SELECT COUNT(*) FROM voters WHERE username = '" + username + "' AND hashed_password = '" + hashed_password + "';";
    PGresult* res = PQexec(conn, query.c_str());

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        cerr << "Query failed: " << PQerrorMessage(conn) << endl;
        PQclear(res);
        PQfinish(conn);
        return false;
    }

    bool login_successful = false;
    if (PQntuples(res) > 0 && atoi(PQgetvalue(res, 0, 0)) > 0) {
        login_successful = true;
    }

    PQclear(res);
    PQfinish(conn);

    return login_successful;
}
// Parse received data (format: "ACTION,username,hashed_password")
void* handle_client(void* socket_desc) {
    int new_socket = *(int*)socket_desc;
    char buffer[BUFFER_SIZE] = {0};

    read(new_socket, buffer, BUFFER_SIZE);
    cout << "Received: " << buffer << endl;

    string data(buffer);
    size_t first_comma_pos = data.find(",");
    size_t second_comma_pos = data.find(",", first_comma_pos + 1);

    if (first_comma_pos != string::npos && second_comma_pos != string::npos) {
        string action = data.substr(0, first_comma_pos); // SIGNUP or LOGIN
        string username = data.substr(first_comma_pos + 1, second_comma_pos - first_comma_pos - 1);
        string hashed_password = data.substr(second_comma_pos + 1);

        if (action == "SIGNUP") {
            insert_into_db(username, hashed_password);
            send(new_socket, "Signup successful", strlen("Signup successful"), 0);
        } else if (action == "LOGIN") {
            bool success = verify_login(username, hashed_password);
            if (success) {
                send(new_socket, "Login successful", strlen("Login successful"), 0);
            } else {
                send(new_socket, "Invalid credentials", strlen("Invalid credentials"), 0);
            }
        } else {
            cerr << "Invalid action received" << endl;
            send(new_socket, "Invalid action", strlen("Invalid action"), 0);
        }
    } else {
        cerr << "Invalid data format" << endl;
        send(new_socket, "Invalid data format", strlen("Invalid data format"), 0);
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

