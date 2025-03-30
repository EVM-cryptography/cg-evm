#include <iostream>
#include <string>
#include <map>
#include <sqlite3.h>
#include "../include/crypto.h"
#include <iomanip>
#define DB_NAME "evote.db"

// Party information
const std::string PARTIES[] = {"BJP", "INC", "TRS"};

// Callback function for SQLite
static int countCallback(void *data, int argc, char **argv, char **azColName) {
    if (argc > 0 && argv[0]) {
        std::map<std::string, int>* counts = static_cast<std::map<std::string, int>*>(data);
        std::string voteHash = argv[0];
        (*counts)[voteHash]++;
    }
    return 0;
}

int main() {
    sqlite3 *db;
    char *zErrMsg = 0;
    int rc;
    
    // Create a map from hash to party name for reverse lookup
    std::map<std::string, std::string> hashToParty;
    for (const auto& party : PARTIES) {
        std::string hash = sha256(party);
        hashToParty[hash] = party;
    }
    
    // Open database
    rc = sqlite3_open(DB_NAME, &db);
    if (rc) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return 1;
    }
    
    // Count votes for each party
    std::map<std::string, int> voteCounts;
    std::string sql = "SELECT voteHash FROM Vote;";
    
    rc = sqlite3_exec(db, sql.c_str(), countCallback, &voteCounts, &zErrMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << zErrMsg << std::endl;
        sqlite3_free(zErrMsg);
        sqlite3_close(db);
        return 1;
    }
    
    // Calculate total votes
    int totalVotes = 0;
    for (const auto& pair : voteCounts) {
        totalVotes += pair.second;
    }
    
    // Print results
    std::cout << "\n==================================================" << std::endl;
    std::cout << "             ELECTION RESULTS                    " << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "Party\t\tVotes\t\tPercentage" << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;
    
    // Process results for each party
    for (const auto& party : PARTIES) {
        std::string hash = sha256(party);
        int votes = voteCounts[hash];
        double percentage = totalVotes > 0 ? (votes * 100.0 / totalVotes) : 0;
        
        std::cout << party << "\t\t" << votes << "\t\t" 
                  << std::fixed << std::setprecision(2) << percentage << "%" << std::endl;
    }
    
    std::cout << "--------------------------------------------------" << std::endl;
    std::cout << "Total Votes:\t" << totalVotes << std::endl;
    std::cout << "==================================================" << std::endl;
    
    // Find the winner
    std::string winningParty;
    int maxVotes = 0;
    
    for (const auto& party : PARTIES) {
        std::string hash = sha256(party);
        if (voteCounts[hash] > maxVotes) {
            maxVotes = voteCounts[hash];
            winningParty = party;
        }
    }
    
    if (maxVotes > 0) {
        std::cout << "\nWINNING PARTY: " << winningParty << " with " << maxVotes << " votes!" << std::endl;
    } else {
        std::cout << "\nNo votes have been cast yet." << std::endl;
    }
    
    sqlite3_close(db);
    return 0;
}