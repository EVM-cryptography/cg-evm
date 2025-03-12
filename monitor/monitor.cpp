#include <iostream>
#include <chrono>
#include <thread>
#include "database.h"

#define DB_NAME "evote.db"

int main() {
    std::cout << "Starting E-Voting database monitor...\n";
    
    while (true) {
        std::cout << "\n============ Database Snapshot ============\n";
        printUsers(DB_NAME);
        printVotes(DB_NAME);
        std::cout << "=============================================\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}