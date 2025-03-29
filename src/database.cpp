//// filepath: /home/vk/Documents/vk_evm/git/cg-evm/src/database.cpp
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
        "hasVoted INTEGER DEFAULT 0, "
        "publicKey TEXT);"
    ) && execSQL(db,
        "CREATE TABLE IF NOT EXISTS Vote ("
        "encUID TEXT, "
        "voteHash TEXT, "
        "signature TEXT);"
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
        sqlite3_bind_text(stmt, static_cast<int>(i + 1),
                          params[i].c_str(), -1, SQLITE_STATIC);
    }
    
    bool result = (sqlite3_step(stmt) == SQLITE_DONE);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

// Original function kept for backward compatibility
bool addUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd) {
    return execPreparedStatement(dbName,
        "INSERT INTO User (hashUID, h1_pwd, hasVoted) VALUES (?,?,0);",
        {hashUID, h1_pwd});
}

// Add user with a public key
bool addUserWithKey(const std::string& dbName, const std::string& hashUID,
                    const std::string& h1, const std::string& publicKey) {
    std::cout << "Adding user with key, key length: " << publicKey.length() << std::endl;
    
    sqlite3* db;
    if(sqlite3_open(dbName.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open DB: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    
    std::string sql =
        "INSERT INTO User (hashUID, h1_pwd, hasVoted, publicKey) "
        "VALUES (?, ?, 0, ?)";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL prepare error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return false;
    }
    
    if (sqlite3_bind_text(stmt, 1, hashUID.c_str(),
                          static_cast<int>(hashUID.size()), SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 2, h1.c_str(),
                          static_cast<int>(h1.size()), SQLITE_STATIC) != SQLITE_OK ||
        sqlite3_bind_text(stmt, 3, publicKey.c_str(),
                          static_cast<int>(publicKey.size()), SQLITE_STATIC) != SQLITE_OK) {
        std::cerr << "SQL bind error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
    
    bool success = (sqlite3_step(stmt) == SQLITE_DONE);
    if (!success) {
        std::cerr << "SQL execution error: " << sqlite3_errmsg(db) << std::endl;
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return success;
}

// Check user credentials
bool checkUser(const std::string &dbName, const std::string &hashUID,
               const std::string &h1_pwd) {
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
        const char* storedH1 =
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
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

// Original function kept for backward compatibility
bool addVote(const std::string &dbName, const std::string &encUID,
             const std::string &voteHash) {
    return execPreparedStatement(dbName,
        "INSERT INTO Vote (encUID, voteHash) VALUES (?,?);",
        {encUID, voteHash});
}

// New function to add vote with signature
bool addVoteWithSignature(const std::string &dbName, const std::string &encUID,
                          const std::string &voteHash,
                          const std::string &signature) {
    return execPreparedStatement(dbName,
        "INSERT INTO Vote (encUID, voteHash, signature) VALUES (?,?,?);",
        {encUID, voteHash, signature});
}

// Get the user's public key
std::string getUserPublicKey(const std::string& dbName, const std::string& hashUID) {
    sqlite3* db = openDB(dbName);
    if(!db) return "";
    
    std::string publicKey;
    std::string sql = "SELECT publicKey FROM User WHERE hashUID=?";
    
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        sqlite3_close(db);
        return "";
    }
    
    if (sqlite3_bind_text(stmt, 1, hashUID.c_str(), -1, SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return "";
    }
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* keyData = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        int keyLen = sqlite3_column_bytes(stmt, 0);
        
        if (keyData && keyLen > 0) {
            publicKey = std::string(keyData, keyLen);
            std::cout << "Retrieved public key, length: " << keyLen << std::endl;
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return publicKey;
}

// Helper to debug contents of User table
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
        const char* publicKey = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        
        std::cout << "hashUID: " << (uid ? uid : "NULL")
                  << ", H1: " << (pwd ? pwd : "NULL")
                  << ", Has Voted: " << (hasVoted ? "Yes" : "No")
                  << ", Has Public Key: " << (publicKey ? "Yes" : "No") << "\n";
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

// Helper to debug contents of Vote table
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
        const char* signature = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        
        std::cout << "Encrypted UID: " << (encUID ? encUID : "NULL")
                  << ", Vote Hash: " << (vote ? vote : "NULL")
                  << ", Has Signature: " << (signature ? "Yes" : "No") << "\n";
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}