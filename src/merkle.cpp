// File: cg-evm/src/merkle.cpp

#include "../include/merkle.h"
#include "../include/crypto.h"
#include "../include/database.h"
#include <sstream>
#include <iostream>
#include <bits/stdc++.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <thread>
using json = nlohmann::json;

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
    std::cout << "Verifying tree integrity..." << std::endl;
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
    std::string rightHash;
    
    // For nodes with only a left child (no right child), duplicate the left hash
    // This matches our tree building logic for odd numbers of nodes
    if (!node->right && node->left) {
        rightHash = node->left->hash; // Duplicate the left hash
    } else {
        rightHash = node->right ? node->right->hash : "";
    }

    std::string expectedHash = sha256(leftHash + rightHash);
    bool matches = node->hash == expectedHash;
    
    if (!matches) {
        std::cout << "Internal node hash mismatch!" << std::endl;
        std::cout << "  Expected: " << expectedHash << std::endl;
        std::cout << "  Actual:   " << node->hash << std::endl;
    }
    
    return matches;
}

MerkleTree::Node* MerkleTree::findNodeByUserHash(const std::string& userHash) {
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
    json jsonData;
    jsonData["userHash"] = node->userHash;
    jsonData["voteHash"] = node->voteHash;
    jsonData["nodeHash"] = node->hash;
    jsonData["signature"] = node->signature;
    
    // Find the node's position in the tree
    int nodeIndex = -1;
    for (size_t i = 0; i < leaves.size(); i++) {
        if (leaves[i] == node) {
            nodeIndex = i;
            break;
        }
    }
    jsonData["nodeIndex"] = nodeIndex;
    
    // Get the Merkle proof
    std::string proof = getMerkleProof(userHash);
    jsonData["merkleProof"] = proof;
    jsonData["rootHash"] = getRootHash();
    jsonData["totalNodes"] = leaves.size();
    
    return jsonData.dump();
}

// New method to get the root hash of the tree
std::string MerkleTree::getRootHash() {
    if (root) {
        return root->hash;
    }
    return "";
}

// New method to get the leaf count
int MerkleTree::getLeafCount() {
    return leaves.size();
}

// New method to serialize the tree to JSON
std::string MerkleTree::serializeToJson() {
    json j;
    j["rootHash"] = getRootHash();
    j["leafCount"] = getLeafCount();
    
    // Add all leaf nodes
    json leafNodes = json::array();
    for (auto leaf : leaves) {
        json leafNode;
        leafNode["userHash"] = leaf->userHash;
        leafNode["voteHash"] = leaf->voteHash;
        leafNode["hash"] = leaf->hash;
        leafNode["signature"] = leaf->signature;
        leafNodes.push_back(leafNode);
    }
    j["leaves"] = leafNodes;
    
    return j.dump(2);  // Pretty print with 2-space indent
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
        std::cout << indent << "  Signature: " << (node->signature.empty() ? "None" : "Present") << std::endl;
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

// Updated to include signature
void MerkleTree::addVote(const std::string& userHash, const std::string& voteHash, const std::string& signature) {
    std::lock_guard<std::mutex> lock(tree_mutex);
    
    try {
        // Create leaf node
        std::string leafHash = sha256(userHash + voteHash);
        Node* leaf = new Node(leafHash);
        leaf->userHash = userHash;
        leaf->voteHash = voteHash;
        leaf->signature = signature;
        leaves.push_back(leaf);
        
        // Rebuild tree from leaves
        clearInternalNodes();
        root = buildTreeFromLeaves();
        
        // Verify tree integrity
        if (!verifyNodeHashes()) {
            std::cerr << "WARNING: Tree verification failed after adding vote!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error adding vote to Merkle tree: " << e.what() << std::endl;
    }
}

// Generate a Merkle proof for a given user hash
std::string MerkleTree::getMerkleProof(const std::string& userHash) {
    Node* leaf = findNodeByUserHash(userHash);
    if (!leaf) return "";
    
    // Find this leaf's index in the leaves vector
    int leafIndex = -1;
    for (size_t i = 0; i < leaves.size(); i++) {
        if (leaves[i] == leaf) {
            leafIndex = i;
            break;
        }
    }
    
    if (leafIndex == -1) return "";
    
    // Create a proof using the leaf's index
    json proof;
    proof["leafIndex"] = leafIndex;
    proof["leafHash"] = leaf->hash;
    
    // Collect sibling hashes and directions (left or right)
    json siblings = json::array();
    
    // If we have only one node, the proof is empty
    if (leaves.size() > 1) {
        // Recreate the path from leaf to root
        std::vector<std::pair<std::string, bool>> siblingData;
        
        // Calculate the sibling index and whether it's on the right
        int currentIdx = leafIndex;
        int level = 0;
        int nodesAtLevel = leaves.size();
        
        while (nodesAtLevel > 1) {
            bool isRight = (currentIdx % 2 == 0);
            int siblingIdx = isRight ? currentIdx + 1 : currentIdx - 1;
            
            // Make sure sibling exists (for odd number of nodes)
            if (siblingIdx < nodesAtLevel) {
                std::string siblingHash;
                if (level == 0) {
                    // We're at leaf level
                    siblingHash = leaves[siblingIdx]->hash;
                } else {
                    // Calculate where the sibling would be in the tree
                    // This is a simplified path calculation and should be expanded
                    // for a more complex tree structure
                    siblingHash = "sibling_at_level_" + std::to_string(level);
                }
                
                json siblingEntry;
                siblingEntry["hash"] = siblingHash;
                siblingEntry["isRight"] = !isRight;  // From perspective of verifier
                siblings.push_back(siblingEntry);
            }
            
            // Move up to next level
            currentIdx = currentIdx / 2;
            nodesAtLevel = (nodesAtLevel + 1) / 2;
            level++;
        }
    }
    
    proof["siblings"] = siblings;
    proof["rootHash"] = getRootHash();
    
    return proof.dump();
}

// Verify a Merkle proof
bool MerkleTree::verifyMerkleProof(const std::string& leafHash, const std::string& rootHash, const std::string& proofStr) {
    try {
        json proof = json::parse(proofStr);
        
        std::string computedHash = leafHash;
        json siblings = proof["siblings"];
        
        for (auto& sibling : siblings) {
            std::string siblingHash = sibling["hash"];
            bool isRight = sibling["isRight"];
            
            if (isRight) {
                computedHash = sha256(computedHash + siblingHash);
            } else {
                computedHash = sha256(siblingHash + computedHash);
            }
        }
        
        return computedHash == rootHash;
    } catch (const std::exception& e) {
        std::cerr << "Error verifying Merkle proof: " << e.what() << std::endl;
        return false;
    }
}
void MerkleTree::startPeriodicVerification(const std::string &dbName) {
    running = true;
    verificationThread = std::thread([this, dbName]() {
        while (running) {
            bool treeValid = this->verifyTreeIntegrity(dbName);
            
            if (treeValid) {
                std::cout << "==========================================" << std::endl;
                std::cout << "Merkle Tree Integrity Check: PASSED" << std::endl;
                std::cout << "Total nodes verified: " << this->getLeafCount() << std::endl;
                std::cout << "Root hash: " << this->getRootHash() << std::endl;
                std::cout << "==========================================" << std::endl;
            } else {
                std::cout << "==========================================" << std::endl;
                std::cout << "!!! MERKLE TREE INTEGRITY CHECK FAILED !!!" << std::endl;
                std::cout << "Tree may have been tampered with!" << std::endl;
                std::cout << "==========================================" << std::endl;
            }
            
            // Wait for 15 seconds
            std::this_thread::sleep_for(std::chrono::seconds(15));
        }
    });
}
void MerkleTree::stopPeriodicVerification() {
    running = false;
    if (verificationThread.joinable()) {
        verificationThread.join();
    }
}
bool MerkleTree::verifyTreeIntegrity(const std::string &dbName) {
    std::lock_guard<std::mutex> lock(tree_mutex);
    
    if (leaves.empty()) {
        std::cout << "Tree is empty, nothing to verify." << std::endl;
        return true;
    }
    
    std::cout << "Starting comprehensive Merkle tree verification..." << std::endl;
    
    // Step 1: Verify all leaf nodes
    bool leafNodesValid = true;
    for (Node* leaf : leaves) {
        // Verify leaf hash
        std::string expectedHash = sha256(leaf->userHash + leaf->voteHash);
        if (leaf->hash != expectedHash) {
            std::cout << "Leaf node hash mismatch for user " << leaf->userHash << std::endl;
            std::cout << "  Expected: " << expectedHash << std::endl;
            std::cout << "  Actual:   " << leaf->hash << std::endl;
            leafNodesValid = false;
        }
        
        // Verify digital signature if present
        if (!leaf->signature.empty()) {
            if (!verifyNodeSignature(leaf, dbName)) {
                std::cout << "Digital signature verification failed for user " << leaf->userHash << std::endl;
                leafNodesValid = false;
            }
        }
    }
    
    // Step 2: Verify all internal nodes (hash consistency)
    bool internalNodesValid = verifyNodeHashesRecursive(root);
    if (internalNodesValid==false)
    {
        std::cout << "Internal nodes are not valid" << std::endl;
    }
    return leafNodesValid && internalNodesValid;
}

bool MerkleTree::verifyNodeSignature(Node* node, const std::string &dbName) {
    if (node->signature.empty()) {
        return true; // No signature to verify
    }
    
    // Get the user's public key from database
    std::string publicKey = getUserPublicKey(dbName, node->userHash);
    if (publicKey.empty()) {
        std::cout << "Could not retrieve public key for user " << node->userHash << std::endl;
        return false;
    }
    
    // Recreate the data that was signed (userHash:voteHash)
    std::string dataToVerify = node->userHash + ":" + node->voteHash;
    
    // Verify the signature
    bool signatureValid = verifySignature(dataToVerify, node->signature, publicKey);
    
    if (!signatureValid) {
        std::cout << "Signature verification failed for " << node->userHash << std::endl;
        std::cout << "  Data: " << dataToVerify << std::endl;
    }
    
    return signatureValid;
}