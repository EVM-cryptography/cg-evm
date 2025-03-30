#ifndef MERKLE_H
#define MERKLE_H

#include <vector>
#include <string>
#include <mutex>
#include <thread>

class MerkleTree {
public:
    struct Node {
        std::string hash;
        std::string userHash;
        std::string voteHash;
        std::string signature;  // New field for digital signature
        Node* left;
        Node* right;
        
        Node(const std::string& h) : hash(h), left(nullptr), right(nullptr) {}
        ~Node() {}
    };
    
    Node* root;
    std::vector<Node*> leaves;
    std::mutex tree_mutex;
    bool running;
    std::thread verificationThread;
    
    // Helper methods
    Node* buildTreeFromLeaves();
    void clearInternalNodes();
    void printTreeRecursive(Node* node, int depth);
    int calculateTreeHeight(Node* node);
    bool verifyNodeHashesRecursive(Node* node);
    bool verifyNodeSignature(Node* node, const std::string &dbName);

public:
    MerkleTree() : root(nullptr), running(false) {}
    ~MerkleTree();
    
    // Updated to include signature
    void addVote(const std::string& userHash, const std::string& voteHash, const std::string& signature = "");
    std::string getRootHash();
    int getLeafCount();
    std::string serializeToJson();
    void printTree();
    Node* findNodeByUserHash(const std::string& userHash);
    std::string getNodeInfo(const std::string& userHash);
    bool verifyNodeHashes();
    
    // New function for generating proofs
    std::string getMerkleProof(const std::string& userHash);
    bool verifyMerkleProof(const std::string& leafHash, const std::string& rootHash, const std::string& proof);
    
    // New periodic verification functions
    void startPeriodicVerification(const std::string &dbName);
    void stopPeriodicVerification();
    bool verifyTreeIntegrity(const std::string &dbName);
};

#endif