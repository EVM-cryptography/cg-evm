#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <vector>

// Existing functions
std::string sha256(const std::string &input);
std::string aes256_encrypt(const std::string &plaintext, const std::string &key);
std::string aes256_decrypt(const std::string &ciphertext, const std::string &key);

// New functions for digital signatures
bool generateKeyPair(std::string& publicKeyPEM, std::string& privateKeyPEM);
std::string signData(const std::string& data, const std::string& privateKeyPEM);
bool verifySignature(const std::string& data, const std::string& signature, const std::string& publicKeyPEM);

// Base64 encoding/decoding
std::string base64Encode(const unsigned char* buffer, size_t length);
std::vector<unsigned char> base64Decode(const std::string& encoded);

// Utility functions
std::string bytesToHex(const unsigned char* data, size_t len);
std::vector<unsigned char> hexToBytes(const std::string &hex);

// Key storage helpers
bool saveKeyToFile(const std::string& filename, const std::string& key, const std::string& password);
std::string loadKeyFromFile(const std::string& filename, const std::string& password);

#endif