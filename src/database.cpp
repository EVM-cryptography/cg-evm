#include "database.h"
#include <sqlite3.h>
#include <iostream>
#include <sstream>

bool initDatabase(const std::string &dbName) {
    sqlite3 *db;
    char *errMsg = 0;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n";
        return false;
    }
    // Create the User table.
    std::string sqlUser = "CREATE TABLE IF NOT EXISTS User ("
                          "hashUID TEXT PRIMARY KEY, "
                          "h1_pwd TEXT NOT NULL);";
    if (sqlite3_exec(db, sqlUser.c_str(), 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error (User table): " << errMsg << "\n";
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return false;
    }
    // Create the Vote table.
    std::string sqlVote = "CREATE TABLE IF NOT EXISTS Vote ("
                          "encUID TEXT, "
                          "voteHash TEXT);";
    if (sqlite3_exec(db, sqlVote.c_str(), 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error (Vote table): " << errMsg << "\n";
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return false;
    }
    sqlite3_close(db);
    return true;
}

bool addUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database in addUser.\n";
        return false;
    }
    std::string sql = "INSERT INTO User (hashUID, h1_pwd) VALUES (?,?);";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, h1_pwd.c_str(), -1, SQLITE_STATIC);
    
    if(sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error inserting user. (User may already exist.)\n";
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}

bool checkUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database in checkUser.\n";
        return false;
    }
    std::string sql = "SELECT h1_pwd FROM User WHERE hashUID = ?;";
    sqlite3_stmt *stmt;
    bool valid = false;
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
        if(sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *storedH1 = sqlite3_column_text(stmt, 0);
            if(storedH1 && h1_pwd == reinterpret_cast<const char*>(storedH1)) {
                valid = true;
            }
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return valid;
}

bool addVote(const std::string &dbName, const std::string &encUID, const std::string &voteHash) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database in addVote.\n";
        return false;
    }
    std::string sql = "INSERT INTO Vote (encUID, voteHash) VALUES (?,?);";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    sqlite3_bind_text(stmt, 1, encUID.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, voteHash.c_str(), -1, SQLITE_STATIC);
    
    if(sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Error inserting vote.\n";
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}

void printUsers(const std::string &dbName) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database in printUsers.\n";
        return;
    }
    std::string sql = "SELECT * FROM User;";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        std::cout << "----- User Table -----\n";
        while(sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *uid = sqlite3_column_text(stmt, 0);
            const unsigned char *pwd = sqlite3_column_text(stmt, 1);
            std::cout << "hashUID: " << (uid ? reinterpret_cast<const char*>(uid) : "NULL")
                      << ", H1: " << (pwd ? reinterpret_cast<const char*>(pwd) : "NULL") << "\n";
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void printVotes(const std::string &dbName) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database in printVotes.\n";
        return;
    }
    std::string sql = "SELECT * FROM Vote;";
    sqlite3_stmt *stmt;
    if(sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        std::cout << "----- Vote Table -----\n";
        while(sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *encUID = sqlite3_column_text(stmt, 0);
            const unsigned char *vote = sqlite3_column_text(stmt, 1);
            std::cout << "Encrypted UID: " << (encUID ? reinterpret_cast<const char*>(encUID) : "NULL")
                      << ", Vote Hash: " << (vote ? reinterpret_cast<const char*>(vote) : "NULL") << "\n";
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}