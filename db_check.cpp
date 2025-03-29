// db_check.cpp - A tool to diagnose database issues
#include <iostream>
#include <string>
#include <sqlite3.h>
#include <filesystem>

int main() {
    // Check if the database file exists
    if (!std::filesystem::exists("evote.db")) {
        std::cout << "Database file 'evote.db' does not exist!\n";
        std::cout << "Run the server first to initialize the database.\n";
        return 1;
    }
    
    std::cout << "Database file exists. Size: " 
              << std::filesystem::file_size("evote.db") << " bytes\n";
    
    sqlite3* db;
    if (sqlite3_open("evote.db", &db) != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    
    // Check what tables exist
    sqlite3_stmt* stmt;
    const char* query = "SELECT name FROM sqlite_master WHERE type='table'";
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }
    
    std::cout << "Tables in database:\n";
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* tableName = (const char*)sqlite3_column_text(stmt, 0);
        std::cout << "- " << tableName << "\n";
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}