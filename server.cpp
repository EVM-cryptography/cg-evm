#include <iostream>
#include <libpq-fe.h>

void checkExecStatus(PGconn *conn, PGresult *res) {
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        std::cerr << "Query failed: " << PQerrorMessage(conn) << std::endl;
        PQclear(res);
        PQfinish(conn);
        exit(1);
    }
    PQclear(res);
}

int main() {
    const char *conninfo = "dbname=voters user=postgres password=evm hostaddr=127.0.0.1 port=5432";
    PGconn *conn = PQconnectdb(conninfo);

    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "Connection failed: " << PQerrorMessage(conn) << std::endl;
        PQfinish(conn);
        return 1;
    }

    std::string name;
    int age;
    
    std::cout << "Enter name: ";
    std::getline(std::cin, name);
    std::cout << "Enter age: ";
    std::cin >> age;

    std::string query = "INSERT INTO users (name, age) VALUES ('" + name + "', " + std::to_string(age) + ");";

    PGresult *res = PQexec(conn, query.c_str());
    checkExecStatus(conn, res);

    std::cout << "Data inserted successfully!" << std::endl;

    PQfinish(conn);
    return 0;
}

