#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <string>
#include "database.h"
#include <vector>
#include <utility> 
#include <sstream>



#define DB_NAME "evote.db"

// Function to print a horizontal line
void printLine(int width) {
    std::cout << std::setfill('-') << std::setw(width) << "-" << std::endl;
    std::cout << std::setfill(' '); // Reset fill character
}

// Function to print users in tabular format
void printUsersTabular(const char* dbName) {
    std::cout << "\n=== REGISTERED USERS ===\n";
    
    // Define column widths
    const int uidWidth = 15;
    const int hashWidth = 40;
    const int statusWidth = 15;
    const int dateWidth = 20;
    const int totalWidth = uidWidth + hashWidth + statusWidth + dateWidth + 5; // +5 for separators
    
    // Print table header
    printLine(totalWidth);
    std::cout << "| " << std::left << std::setw(uidWidth) << "UID"
              << "| " << std::setw(hashWidth) << "Hash UID"
              << "| " << std::setw(statusWidth) << "Status"
              << "| " << std::setw(dateWidth) << "Registration Date" << "|" << std::endl;
    printLine(totalWidth);
    
    // Redirect cout to capture output from printUsers
    std::streambuf* old_cout = std::cout.rdbuf();
    std::stringstream ss;
    std::cout.rdbuf(ss.rdbuf());
    
    // Call the original printUsers function
    printUsers(dbName);
    
    // Restore cout
    std::cout.rdbuf(old_cout);
    
    // Parse the output and format it as a table
    std::string line;
    while (std::getline(ss, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        // Parse the line based on your printUsers output format
        // This is an example - adjust according to your actual output format
        std::stringstream lineStream(line);
        std::string uid, hashUid, status, date;
        
        // Assuming format: "UID: uid, Hash: hashUid, Status: status, Date: date"
        // Parse the line according to your actual output format
        if (line.find("UID:") != std::string::npos) {
            size_t uidPos = line.find("UID:") + 5;
            size_t hashPos = line.find("Hash:") + 6;
            size_t statusPos = line.find("Status:") + 8;
            size_t datePos = line.find("Date:") + 6;
            
            uid = line.substr(uidPos, line.find("Hash:") - uidPos - 2);
            hashUid = line.substr(hashPos, line.find("Status:") - hashPos - 2);
            status = line.substr(statusPos, line.find("Date:") - statusPos - 2);
            date = line.substr(datePos);
            
            std::cout << "| " << std::left << std::setw(uidWidth) << uid
                      << "| " << std::setw(hashWidth) << hashUid
                      << "| " << std::setw(statusWidth) << status
                      << "| " << std::setw(dateWidth) << date << "|" << std::endl;
        }
    }
    
    printLine(totalWidth);
}

// Function to print votes in tabular format
void printVotesTabular(const char* dbName) {
    std::cout << "\n=== VOTE DISTRIBUTION ===\n";
    
    // Define column widths
    const int partyWidth = 15;
    const int countWidth = 15;
    const int percentWidth = 15;
    const int totalWidth = partyWidth + countWidth + percentWidth + 4; // +4 for separators
    
    // Print table header
    printLine(totalWidth);
    std::cout << "| " << std::left << std::setw(partyWidth) << "Party"
              << "| " << std::setw(countWidth) << "Vote Count"
              << "| " << std::setw(percentWidth) << "Percentage" << "|" << std::endl;
    printLine(totalWidth);
    
    // Redirect cout to capture output from printVotes
    std::streambuf* old_cout = std::cout.rdbuf();
    std::stringstream ss;
    std::cout.rdbuf(ss.rdbuf());
    
    // Call the original printVotes function
    printVotes(dbName);
    
    // Restore cout
    std::cout.rdbuf(old_cout);
    
    // Parse the output and format it as a table
    std::string line;
    int totalVotes = 0;
    std::vector<std::pair<std::string, int>> voteData;
    
    // First pass: collect data and calculate total
    while (std::getline(ss, line)) {
        // Skip empty lines
        if (line.empty()) continue;
        
        // Parse the line based on your printVotes output format
        // This is an example - adjust according to your actual output format
        if (line.find("Party:") != std::string::npos) {
            size_t partyPos = line.find("Party:") + 7;
            size_t countPos = line.find("Count:") + 7;
            
            std::string party = line.substr(partyPos, line.find("Count:") - partyPos - 2);
            int count = std::stoi(line.substr(countPos));
            
            voteData.push_back({party, count});
            totalVotes += count;
        }
    }
    
    // Second pass: print formatted data with percentages
    for (const auto& vote : voteData) {
        float percentage = (totalVotes > 0) ? 
            (static_cast<float>(vote.second) / totalVotes) * 100.0 : 0.0;
        
        std::cout << "| " << std::left << std::setw(partyWidth) << vote.first
                  << "| " << std::setw(countWidth) << vote.second
                  << "| " << std::setw(percentWidth) << std::fixed << std::setprecision(2) << percentage << "% |" << std::endl;
    }
    
    printLine(totalWidth);
}

int main() {
    std::cout << "Starting E-Voting database monitor...\n";
    
    while (true) {
        std::cout << "\n============ Database Snapshot ============\n";
        printUsersTabular(DB_NAME);
        printVotesTabular(DB_NAME);
        std::cout << "=============================================\n";
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }
}
