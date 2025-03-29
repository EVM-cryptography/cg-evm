#ifndef DATABASE_H
#define DATABASE_H

#include <string>

// Initializes (or creates) the SQLite database with the required tables.
bool initDatabase(const std::string &dbName);

// Adds a new user record to the "User" table.
bool addUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd);

// New: Adds a user with public key
bool addUserWithKey(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd, const std::string &publicKey);

// Checks if the provided hashUID and h1 match an existing user.
bool checkUser(const std::string &dbName, const std::string &hashUID, const std::string &h1_pwd);

// Records a vote to the "Vote" table and marks the user as having voted.
bool addVote(const std::string &dbName, const std::string &encUID, const std::string &voteHash);

// New: Add vote with signature
bool addVoteWithSignature(const std::string &dbName, const std::string &encUID, const std::string &voteHash, const std::string &signature);

// Prints the contents of the "User" table (for monitoring purposes).
void printUsers(const std::string &dbName);

// Prints the contents of the "Vote" table (for monitoring purposes).
void printVotes(const std::string &dbName);

// Check if a user has already voted
bool hasUserVoted(const std::string &dbName, const std::string &hashUID);

// Mark a user as having voted
bool markUserAsVoted(const std::string &dbName, const std::string &hashUID);

// New: Get user's public key
std::string getUserPublicKey(const std::string &dbName, const std::string &hashUID);

#endif