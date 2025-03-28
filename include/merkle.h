#ifndef MERKLE_H
#define MERKLE_H

#include <vector>
#include <string>
#include <mutex>

class MerkleTree {
public:
    struct Node {
        std::string hash;
        std::string userHash;
        std::string voteHash;
        Node* left;
        Node* right;
        
        Node(const std::string& h) : hash(h), left(nullptr), right(nullptr) {}
        ~Node() {}
    };
    
    Node* root;
    std::vector<Node*> leaves;
    std::mutex tree_mutex;
    
    // Helper methods
    Node* buildTreeFromLeaves();
    void clearInternalNodes();
    void printTreeRecursive(Node* node, int depth);
    int calculateTreeHeight(Node* node);
    bool verifyNodeHashesRecursive(Node* node);

public:
    MerkleTree() : root(nullptr) {}
    ~MerkleTree();
    
    void addVote(const std::string& userHash, const std::string& voteHash);
    std::string getRootHash();
    int getLeafCount();
    std::string serializeToJson();
    void printTree();
    Node* findNodeByUserHash(const std::string& userHash);
    std::string getNodeInfo(const std::string& userHash);
    bool verifyNodeHashes();
};

#endif
