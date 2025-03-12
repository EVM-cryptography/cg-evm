#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <sstream>
#include <iomanip>
#include <vector>

// Optimized hex string conversion
std::string bytesToHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; i++) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(static_cast<unsigned char>(
            strtol(hex.substr(i, 2).c_str(), nullptr, 16)));
    }
    return bytes;
}

std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

std::string aes256_encrypt(const std::string &plaintext, const std::string &keyHex) {
    // Convert key from hex to binary
    std::vector<unsigned char> key = hexToBytes(keyHex);
    if(key.size() != 32) return "";  // AES-256 needs 32-byte key
    
    // Fixed IV for compatibility with existing code
    unsigned char iv[16] = {0};

    // Initialize context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return "";

    // Initialize encryption operation
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    // Allocate output buffer (plaintext + block size for padding)
    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len, ciphertext_len;

    // Encrypt data
    if(EVP_EncryptUpdate(ctx, ciphertext.data(), &len, 
                       reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                       plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    // Finalize encryption
    if(EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return bytesToHex(ciphertext.data(), ciphertext_len);
}

std::string aes256_decrypt(const std::string &cipherHex, const std::string &keyHex) {
    std::vector<unsigned char> key = hexToBytes(keyHex);
    if(key.size() != 32) return "";
    
    std::vector<unsigned char> cipherBytes = hexToBytes(cipherHex);
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return "";

    if(EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(cipherBytes.size()); // Will be at most this size
    int len, plaintext_len;
    
    if(EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipherBytes.data(), cipherBytes.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if(EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}