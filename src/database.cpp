#include "database.h"
#include <sqlite3.h>
#include <iostream>
#include <vector>

// Open database connection with error handling
sqlite3* openDB(const std::string &dbName) {
    sqlite3 *db;
    if (sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(db) << "\n";
        sqlite3_close(db);
        return nullptr;
    }
    return db;
}

// Execute a simple SQL statement
bool execSQL(sqlite3 *db, const std::string &sql) {
    char *errMsg = nullptr;
    bool success = (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) == SQLITE_OK);
    if (!success) {
        std::cerr << "SQL error: " << (errMsg ? errMsg : "unknown") << "\n";
        sqlite3_free(errMsg);
    }
    return success;
}

bool initDatabase(const std::string &dbName) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    bool success = execSQL(db, 
        "CREATE TABLE IF NOT EXISTS User ("
        "hashUID TEXT PRIMARY KEY, "
        "h1_pwd TEXT NOT NULL, "
        "hasVoted INTEGER DEFAULT 0);"
    ) && execSQL(db, 
        "CREATE TABLE IF NOT EXISTS Vote ("
        "encUID TEXT, "
        "voteHash TEXT);"
    );
    
    sqlite3_close(db);
    return success;
}

// Execute a prepared statement that returns a boolean result
bool execPreparedStatement(const std::string &dbName, const std::string &sql,
                          const std::vector<std::string> &params) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    // Bind parameters
    for (size_t i = 0; i < params.size(); i++) {
        sqlite3_bind_text(stmt, i+1, params[i].c_str(), -1, SQLITE_STATIC);
    }
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

bool addUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    return execPreparedStatement(dbName, 
        "INSERT INTO User (hashUID, h1_pwd, hasVoted) VALUES (?,?,0);",
        {hashUID, h1_pwd});
}

bool checkUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT h1_pwd FROM User WHERE hashUID = ?;", -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
    
    bool valid = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* storedH1 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        valid = (storedH1 && h1_pwd == storedH1);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return valid;
}

bool hasUserVoted(const std::string &dbName, const std::string &hashUID) {
    sqlite3 *db = openDB(dbName);
    if (!db) return false;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT hasVoted FROM User WHERE hashUID = ?;", -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC);
    
    bool voted = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        voted = (sqlite3_column_int(stmt, 0) == 1);
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return voted;
}

bool markUserAsVoted(const std::string &dbName, const std::string &hashUID) {
    return execPreparedStatement(dbName,
        "UPDATE User SET hasVoted = 1 WHERE hashUID = ?;",
        {hashUID});
}

bool addVote(const std::string &dbName, const std::string &encUID, const std::string &voteHash) {
    return execPreparedStatement(dbName,
        "INSERT INTO Vote (encUID, voteHash) VALUES (?,?);",
        {encUID, voteHash});
}

void printUsers(const std::string &dbName) {
    sqlite3 *db = openDB(dbName);
    if (!db) return;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT * FROM User;", -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return;
    }
    
    std::cout << "----- User Table -----\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* pwd = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int hasVoted = sqlite3_column_int(stmt, 2);
        
        std::cout << "hashUID: " << (uid ? uid : "NULL")
                  << ", H1: " << (pwd ? pwd : "NULL")
                  << ", Has Voted: " << (hasVoted ? "Yes" : "No") << "\n";
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void printVotes(const std::string &dbName) {
    sqlite3 *db = openDB(dbName);
    if (!db) return;
    
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT * FROM Vote;", -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return;
    }
    
    std::cout << "----- Vote Table -----\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* encUID = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        const char* vote = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        
        std::cout << "Encrypted UID: " << (encUID ? encUID : "NULL")
                  << ", Vote Hash: " << (vote ? vote : "NULL") << "\n";
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}