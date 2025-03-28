#include "../include/merkle.h"
#include "../include/crypto.h"
#include <sstream>
#include <iostream>
#include <bits/stdc++.h>

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
// Verify that all node hashes are correctly computed
bool MerkleTree::verifyNodeHashes() {
    //std::lock_guard<std::mutex> lock(tree_mutex);
    std::cout<<"verifying now"<<std::endl;

    return verifyNodeHashesRecursive(root);
}

bool MerkleTree::verifyNodeHashesRecursive(Node* node) {
    if (!node) return true; // Base case: empty node

    // Check if it's a leaf node
    if (!node->left && !node->right) { // More reliable leaf check
        std::string expectedHash = sha256(node->userHash + node->voteHash);
        return node->hash == expectedHash;
    }

    // Recursively verify child nodes
    bool leftValid = verifyNodeHashesRecursive(node->left);
    bool rightValid = verifyNodeHashesRecursive(node->right);

    if (!leftValid || !rightValid) return false; // If any child is invalid

    std::string leftHash = node->left ? node->left->hash : "";
    std::string rightHash = node->right ? node->right->hash : ""; // Fixed from leftHash

    std::string expectedHash = sha256(leftHash + rightHash);
    return node->hash == expectedHash;
}


MerkleTree::Node* MerkleTree::findNodeByUserHash(const std::string& userHash) {
   //
   //  std::lock_guard<std::mutex> lock(tree_mutex);
    
    // Search through leaf nodes to find the one with matching userHash
    for (auto leaf : leaves) {
        if (leaf->userHash == userHash) {
            return leaf;
        }
    }
    
    return nullptr; // Node not found
}

std::string MerkleTree::getNodeInfo(const std::string& userHash) {
    Node* node = findNodeByUserHash(userHash);
    
    if (!node) {
        return ""; // Node not found
    }
    
    // Create a JSON string with all node information
    std::stringstream json;
    json << "{";
    json << "\"userHash\":\"" << node->userHash << "\",";
    json << "\"voteHash\":\"" << node->voteHash << "\",";
    json << "\"nodeHash\":\"" << node->hash << "\",";
    
    // Find the node's position in the tree
    int nodeIndex = -1;
    for (size_t i = 0; i < leaves.size(); i++) {
        if (leaves[i] == node) {
            nodeIndex = i;
            break;
        }
    }
    
    json << "\"nodeIndex\":" << nodeIndex << ",";
    
    // Get the path from this node to the root
    json << "\"pathToRoot\":[";
    
    // This is a simplified path calculation
    // In a real implementation, you'd need to traverse the tree
    // to build the actual path from leaf to root
    
    Node* current = node;
    std::vector<std::string> path;
    
    // Simplified path generation - in a real implementation,
    // you would need to traverse up the tree
    if (root) {
        path.push_back(root->hash);
    }
    
    for (size_t i = 0; i < path.size(); i++) {
        json << "\"" << path[i] << "\"";
        if (i < path.size() - 1) {
            json << ",";
        }
    }
    
    json << "],";
    json << "\"totalNodes\":" << leaves.size();
    json << "}";
    
    return json.str();
}

void MerkleTree::printTree() {
    std::lock_guard<std::mutex> lock(tree_mutex);
    std::cout << "Merkle Tree Structure:" << std::endl;
    if (root) {
        std::cout << "Total levels: " << calculateTreeHeight(root) << std::endl;
        printTreeRecursive(root, 0);
    } else {
        std::cout << "Tree is empty." << std::endl;
    }
}

// Helper method to calculate tree height
int MerkleTree::calculateTreeHeight(Node* node) {
    if (node == nullptr) return 0;
    return 1 + std::max(calculateTreeHeight(node->left), calculateTreeHeight(node->right));
}

void MerkleTree::printTreeRecursive(Node* node, int depth) {
    if (node == nullptr) return;

    std::string indent(depth * 4, ' '); // 4 spaces per depth level

    std::cout << indent << "Level " << depth << " | Hash: " << node->hash << std::endl;

    // Check if it's a leaf node
    bool isLeaf = std::find(leaves.begin(), leaves.end(), node) != leaves.end();
    if (isLeaf) {
        std::cout << indent << "  Leaf Node Data:" << std::endl;
        std::cout << indent << "  User Hash: " << node->userHash << std::endl;
        std::cout << indent << "  Vote Hash: " << node->voteHash << std::endl;
    }

    if (node->left) printTreeRecursive(node->left, depth + 1);
    if (node->right) printTreeRecursive(node->right, depth + 1);
}

// Build tree from leaves using an iterative approach
MerkleTree::Node* MerkleTree::buildTreeFromLeaves() {
    if (leaves.empty()) return nullptr;
    
    try {
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
    } catch (const std::bad_alloc& e) {
        std::cerr << "Memory allocation failed in buildTreeFromLeaves: " << e.what() << std::endl;
        return nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Error in buildTreeFromLeaves: " << e.what() << std::endl;
        return nullptr;
    }
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

        // Verify all node hashes   
        std::cout << "Verifying all node hashes... ";
        bool ans=verifyNodeHashes();
        if(ans==true)
        {
            std::cout<<"verified"<<std::endl;
        }
        else
        {
            std::cout<<"not verified"<<std::endl;
        }

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
