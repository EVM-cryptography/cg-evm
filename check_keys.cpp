// Check stored keys script (save as check_keys.cpp)
#include <iostream>
#include <string>
#include <sqlite3.h>

int main() {
    sqlite3* db;
    if (sqlite3_open("evote.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    
    sqlite3_stmt* stmt;
    const char* query = "SELECT hashUID, publicKey FROM Users WHERE publicKey IS NOT NULL";
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    
    std::cout << "User Public Keys in Database:\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* uid = (const char*)sqlite3_column_text(stmt, 0);
        const char* key = (const char*)sqlite3_column_text(stmt, 1);
        int keyLength = sqlite3_column_bytes(stmt, 1);
        
        std::cout << "User: " << uid << "\n";
        std::cout << "Public Key Length: " << keyLength << " bytes\n";
        std::cout << "Key Preview: " << std::string(key, std::min(50, keyLength)) << "...\n\n";
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}