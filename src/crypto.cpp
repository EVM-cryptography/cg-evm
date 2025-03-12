#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>

// Helper: Convert a byte array to a hex string.
std::string bytesToHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return oss.str();
}

// Helper: Convert a hex string into a vector of bytes.
std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

std::string aes256_encrypt(const std::string &plaintext, const std::string &keyHex) {
    // Convert key from hex string to binary.
    std::vector<unsigned char> key = hexToBytes(keyHex);
    if(key.size() != 32) {  // AES-256 requires a 32-byte key.
        return "";
    }
    // Using a fixed IV (16 bytes zero) for demo purposes.
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return "";

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
    int len;
    int ciphertext_len = 0;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                              reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                              plaintext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return bytesToHex(ciphertext.data(), ciphertext_len);
}

std::string aes256_decrypt(const std::string &cipherHex, const std::string &keyHex) {
    std::vector<unsigned char> key = hexToBytes(keyHex);
    if(key.size() != 32) {
        return "";
    }
    std::vector<unsigned char> cipherBytes = hexToBytes(cipherHex);
    unsigned char iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) return "";

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    std::vector<unsigned char> plaintext(cipherBytes.size());
    int len;
    int plaintext_len = 0;

    if(1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipherBytes.data(), cipherBytes.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
}