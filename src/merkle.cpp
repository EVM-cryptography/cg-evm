#include "../include/merkle.h"
#include "../include/crypto.h"
#include <sstream>
#include <iostream>

// Destructor to clean up all nodes
MerkleTree::~MerkleTree() {
    clearInternalNodes();
    
    // Delete leaf nodes
    for (auto leaf : leaves) {
        delete leaf;
    }
    leaves.clear();
}

// Clear all internal nodes (non-leaf nodes)
void MerkleTree::clearInternalNodes() {
    if (!root) return;
    
    std::vector<Node*> nodesToDelete;
    std::vector<Node*> queue;
    
    if (root) queue.push_back(root);
    
    // Breadth-first traversal to collect all internal nodes
    while (!queue.empty()) {
        Node* current = queue.front();
        queue.erase(queue.begin());
        
        // Check if this is not a leaf node
        bool isLeaf = false;
        for (auto leaf : leaves) {
            if (current == leaf) {
                isLeaf = true;
                break;
            }
        }
        
        if (!isLeaf) {
            nodesToDelete.push_back(current);
        }
        
        if (current->left) queue.push_back(current->left);
        if (current->right) queue.push_back(current->right);
    }
    
    // Delete all internal nodes
    for (auto node : nodesToDelete) {
        delete node;
    }
    
    root = nullptr;
}

// Build tree from leaves using an iterative approach
MerkleTree::Node* MerkleTree::buildTreeFromLeaves() {
    if (leaves.empty()) return nullptr;
    
    std::vector<Node*> currentLevel = leaves;
    
    while (currentLevel.size() > 1) {
        std::vector<Node*> nextLevel;
        
        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            if (i + 1 < currentLevel.size()) {
                // Two children
                std::string combinedHash = sha256(currentLevel[i]->hash + currentLevel[i+1]->hash);
                Node* parent = new Node(combinedHash);
                parent->left = currentLevel[i];
                parent->right = currentLevel[i+1];
                nextLevel.push_back(parent);
            } else {
                // Single child (duplicate hash for even tree)
                std::string combinedHash = sha256(currentLevel[i]->hash + currentLevel[i]->hash);
                Node* parent = new Node(combinedHash);
                parent->left = currentLevel[i];
                parent->right = nullptr;
                nextLevel.push_back(parent);
            }
        }
        
        currentLevel = nextLevel;
    }
    
    return currentLevel.empty() ? nullptr : currentLevel[0];
}

// Add a new vote to the tree
void MerkleTree::addVote(const std::string& userHash, const std::string& voteHash) {
    std::lock_guard<std::mutex> lock(tree_mutex);
    
    try {
        // Create leaf node with combined hash
        std::string leafHash = sha256(userHash + voteHash);
        Node* leaf = new Node(leafHash);
        leaf->userHash = userHash;
        leaf->voteHash = voteHash;
        leaves.push_back(leaf);
        
        // Clear internal nodes and rebuild tree
        clearInternalNodes();
        root = buildTreeFromLeaves();
        
        std::cout << "Vote added to Merkle tree. New leaf count: " << leaves.size() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error adding vote to Merkle tree: " << e.what() << std::endl;
        // If leaf was added but tree building failed, remove the leaf
        if (!leaves.empty()) {
            delete leaves.back();
            leaves.pop_back();
        }
    }
}

// Get the current root hash
std::string MerkleTree::getRootHash() {
    std::lock_guard<std::mutex> lock(tree_mutex);
    return root ? root->hash : "";
}

// Get the number of leaves (votes)
int MerkleTree::getLeafCount() {
    std::lock_guard<std::mutex> lock(tree_mutex);
    return leaves.size();
}

// Serialize the tree to JSON format
std::string MerkleTree::serializeToJson() {
    std::lock_guard<std::mutex> lock(tree_mutex);
    
    std::stringstream json;
    json << "{\"root_hash\":\"" << (root ? root->hash : "") << "\",";
    json << "\"vote_count\":" << leaves.size() << ",";
    json << "\"votes\":[";
    
    for (size_t i = 0; i < leaves.size(); i++) {
        json << "{\"user_hash\":\"" << leaves[i]->userHash << "\",";
        json << "\"vote_hash\":\"" << leaves[i]->voteHash << "\",";
        json << "\"leaf_hash\":\"" << leaves[i]->hash << "\"}";
        
        if (i < leaves.size() - 1) {
            json << ",";
        }
    }
    
    json << "]}";
    return json.str();
}
