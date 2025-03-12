#include "database.h"
#include <sqlite3.h>
#include <iostream>

// Helper function for database operations to reduce repetitive code
sqlite3* openDB(const std::string &dbName) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db)) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n";
        return nullptr;
    }
    return db;
}

bool initDatabase(const std::string &dbName) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    const char* sqlUser = "CREATE TABLE IF NOT EXISTS User ("
                          "hashUID TEXT PRIMARY KEY, "
                          "h1_pwd TEXT NOT NULL, "
                          "hasVoted INTEGER DEFAULT 0);";
                          
    const char* sqlVote = "CREATE TABLE IF NOT EXISTS Vote ("
                          "encUID TEXT, "
                          "voteHash TEXT);";
    
    char *errMsg = nullptr;
    bool success = true;
    
    if (sqlite3_exec(db, sqlUser, 0, 0, &errMsg) != SQLITE_OK ||
        sqlite3_exec(db, sqlVote, 0, 0, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << (errMsg ? errMsg : "unknown") << "\n";
        sqlite3_free(errMsg);
        success = false;
    }
    
    sqlite3_close(db);
    return success;
}

bool addUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    const char* sql = "INSERT INTO User (hashUID, h1_pwd, hasVoted) VALUES (?,?,0);";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, h1_pwd.c_str(), -1, SQLITE_STATIC);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

bool checkUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    const char* sql = "SELECT h1_pwd FROM User WHERE hashUID = ?;";
    bool valid = false;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *storedH1 = sqlite3_column_text(stmt, 0);
            valid = (storedH1 && h1_pwd == reinterpret_cast<const char*>(storedH1));
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return valid;
}

bool hasUserVoted(const std::string &dbName, const std::string &hashUID) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    const char* sql = "SELECT hasVoted FROM User WHERE hashUID = ?;";
    bool voted = false;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            voted = sqlite3_column_int(stmt, 0) == 1;
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return voted;
}

bool markUserAsVoted(const std::string &dbName, const std::string &hashUID) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    const char* sql = "UPDATE User SET hasVoted = 1 WHERE hashUID = ?;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

bool addVote(const std::string &dbName, const std::string &encUID, const std::string &voteHash) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    const char* sql = "INSERT INTO Vote (encUID, voteHash) VALUES (?,?);";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, encUID.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, voteHash.c_str(), -1, SQLITE_STATIC);
    
    bool result = sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

void printUsers(const std::string &dbName) {
    sqlite3 *db = openDB(dbName);
    if (!db) return;
    
    sqlite3_stmt *stmt;
    const char* sql = "SELECT * FROM User;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::cout << "----- User Table -----\n";
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const char* pwd = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            int hasVoted = sqlite3_column_int(stmt, 2);
            
            std::cout << "hashUID: " << (uid ? uid : "NULL")
                      << ", H1: " << (pwd ? pwd : "NULL")
                      << ", Has Voted: " << (hasVoted ? "Yes" : "No") << "\n";
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void printVotes(const std::string &dbName) {
    sqlite3 *db = openDB(dbName);
    if (!db) return;
    
    sqlite3_stmt *stmt;
    const char* sql = "SELECT * FROM Vote;";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        std::cout << "----- Vote Table -----\n";
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* encUID = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const char* vote = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            
            std::cout << "Encrypted UID: " << (encUID ? encUID : "NULL")
                      << ", Vote Hash: " << (vote ? vote : "NULL") << "\n";
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}