#include "../include/crypto.h"
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <vector>
#include <iostream>
#include <algorithm>

// Initialize OpenSSL
static bool opensslInitialized = false;

// Debug print function for crypto operations
void cryptoDebugPrint(const std::string& message) {
    std::cout << "CRYPTO DEBUG: " << message << std::endl;
}

void initOpenSSL() {
    if (!opensslInitialized) {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
        opensslInitialized = true;
    }
}

// SHA-256 implementation
std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, input.c_str(), input.size());
    SHA256_Final(hash, &sha256Context);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Base64 encode function
std::string base64Encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return result;
}

// Base64 decode function
std::vector<unsigned char> base64Decode(const std::string& input) {
    BIO *bio, *b64;
    
    int decodeLen = input.size();
    std::vector<unsigned char> buffer(decodeLen);

    bio = BIO_new_mem_buf(input.c_str(), -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    
    int length = BIO_read(bio, buffer.data(), decodeLen);
    buffer.resize(length);
    
    BIO_free_all(bio);
    
    return buffer;
}

// AES-256 encryption
std::string aes256_encrypt(const std::string& plaintext, const std::string& key) {
    initOpenSSL();
    
    // Use the first 32 bytes of the key (SHA-256 output) as AES key
    unsigned char aes_key[32];
    memcpy(aes_key, key.c_str(), std::min(key.length(), size_t(32)));
    
    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        cryptoDebugPrint("Failed to generate random IV");
        return "";
    }
    
    // Setup encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cryptoDebugPrint("Failed to create cipher context");
        return "";
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        cryptoDebugPrint("Failed to initialize encryption");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Allocate enough space for the output
    std::vector<unsigned char> ciphertext(plaintext.length() + AES_BLOCK_SIZE);
    int outlen1 = 0, outlen2 = 0;
    
    // Encrypt the plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen1, 
                         (const unsigned char*)plaintext.c_str(), plaintext.length()) != 1) {
        cryptoDebugPrint("Failed during encryption update");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Finalize the encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen1, &outlen2) != 1) {
        cryptoDebugPrint("Failed during encryption finalization");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize to actual output size
    ciphertext.resize(outlen1 + outlen2);
    
    // Prepend the IV to the ciphertext
    std::vector<unsigned char> result(iv, iv + AES_BLOCK_SIZE);
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    
    // Return base64 encoded result
    std::string encoded = base64Encode(result.data(), result.size());
    cryptoDebugPrint("Encrypted data (size: " + std::to_string(encoded.length()) + ")");
    return encoded;
}

// AES-256 decryption
std::string aes256_decrypt(const std::string& ciphertext_b64, const std::string& key) {
    initOpenSSL();
    
    cryptoDebugPrint("Decrypting data (encoded size: " + std::to_string(ciphertext_b64.length()) + ")");
    
    // Decode base64
    std::vector<unsigned char> ciphertext_raw = base64Decode(ciphertext_b64);
    if (ciphertext_raw.size() <= AES_BLOCK_SIZE) {
        cryptoDebugPrint("Decoded data too short for IV + content: " + std::to_string(ciphertext_raw.size()));
        return ""; // Too short, can't contain IV + data
    }
    
    // Extract IV from the beginning
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ciphertext_raw.data(), AES_BLOCK_SIZE);
    
    // Use the first 32 bytes of the key (SHA-256 output) as AES key
    unsigned char aes_key[32];
    memcpy(aes_key, key.c_str(), std::min(key.length(), size_t(32)));
    
    // Setup decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        cryptoDebugPrint("Failed to create cipher context for decryption");
        return "";
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        cryptoDebugPrint("Failed to initialize decryption");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Allocate space for the decrypted result
    size_t ciphertext_len = ciphertext_raw.size() - AES_BLOCK_SIZE;
    std::vector<unsigned char> plaintext(ciphertext_len + AES_BLOCK_SIZE); // Add space for padding
    int outlen1 = 0, outlen2 = 0;
    
    // Decrypt the ciphertext
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen1, 
                         ciphertext_raw.data() + AES_BLOCK_SIZE, ciphertext_len) != 1) {
        cryptoDebugPrint("Failed during decryption update");
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    // Finalize the decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen1, &outlen2) != 1) {
        // Get error information
        unsigned long errCode = ERR_get_error();
        char errBuf[256];
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        cryptoDebugPrint("Failed during decryption finalization: " + std::string(errBuf));
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Resize to actual output size and convert to string
    plaintext.resize(outlen1 + outlen2);
    std::string result(plaintext.begin(), plaintext.end());
    cryptoDebugPrint("Decrypted data successfully (length: " + std::to_string(result.length()) + ")");
    return result;
}

// Utility function to strip PEM headers and whitespace - kept for backward compatibility
// but no longer used in the key generation flow
std::string stripPEMFormatting(const std::string& pemData) {
    std::string result;
    bool inHeader = false;
    bool inFooter = false;
    
    for (size_t i = 0; i < pemData.length(); i++) {
        // Check for header start
        if (i + 10 < pemData.length() && 
            pemData.substr(i, 5) == "-----" && 
            pemData.substr(i + 5, 5).find("BEGIN") != std::string::npos) {
            inHeader = true;
            continue;
        }
        
        // Check for header end
        if (inHeader && pemData[i] == '-' && i + 4 < pemData.length() && 
            pemData.substr(i, 5) == "-----") {
            inHeader = false;
            continue;
        }
        
        // Check for footer start
        if (i + 8 < pemData.length() && 
            pemData.substr(i, 5) == "-----" && 
            pemData.substr(i + 5, 3).find("END") != std::string::npos) {
            inFooter = true;
            continue;
        }
        
        // Check for footer end
        if (inFooter && pemData[i] == '-' && i + 4 < pemData.length() && 
            pemData.substr(i, 5) == "-----") {
            inFooter = false;
            continue;
        }
        
        // Skip headers and footers
        if (inHeader || inFooter) {
            continue;
        }
        
        // Skip whitespace
        if (!std::isspace(pemData[i])) {
            result += pemData[i];
        }
    }
    
    return result;
}

// FIXED: Generate RSA key pair - returns FULL PEM formatted keys with headers
bool generateKeyPair(std::string& publicKey, std::string& privateKey) {
    initOpenSSL();
    
    cryptoDebugPrint("Generating new 2048-bit RSA key pair");
    
    // Create key pair
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        cryptoDebugPrint("Failed to create EVP_PKEY object");
        return false;
    }
    
    // Initialize RSA context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        cryptoDebugPrint("Failed to create key generation context");
        EVP_PKEY_free(pkey);
        return false;
    }
    
    // Set up key generation parameters
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        cryptoDebugPrint("Failed to initialize key generation");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        cryptoDebugPrint("Failed to set RSA key size");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        cryptoDebugPrint("Key generation failed");
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Extract public key in PEM format
    BIO* pubBio = BIO_new(BIO_s_mem());
    if (!pubBio) {
        cryptoDebugPrint("Failed to create BIO for public key");
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (PEM_write_bio_PUBKEY(pubBio, pkey) <= 0) {
        cryptoDebugPrint("Failed to write public key to BIO");
        EVP_PKEY_free(pkey);
        BIO_free_all(pubBio);
        return false;
    }
    
    BUF_MEM* pubPtr;
    BIO_get_mem_ptr(pubBio, &pubPtr);
    std::string pubPem(pubPtr->data, pubPtr->length);
    BIO_free_all(pubBio);
    
    // Extract private key in PEM format
    BIO* privBio = BIO_new(BIO_s_mem());
    if (!privBio) {
        cryptoDebugPrint("Failed to create BIO for private key");
        EVP_PKEY_free(pkey);
        return false;
    }
    
    if (PEM_write_bio_PrivateKey(privBio, pkey, NULL, NULL, 0, NULL, NULL) <= 0) {
        cryptoDebugPrint("Failed to write private key to BIO");
        EVP_PKEY_free(pkey);
        BIO_free_all(privBio);
        return false;
    }
    
    BUF_MEM* privPtr;
    BIO_get_mem_ptr(privBio, &privPtr);
    std::string privPem(privPtr->data, privPtr->length);
    BIO_free_all(privBio);
    
    EVP_PKEY_free(pkey);
    
    // FIXED: Use the full PEM format with headers instead of stripping them
    publicKey = pubPem;
    privateKey = privPem;
    
    cryptoDebugPrint("Key pair generated successfully");
    cryptoDebugPrint("Public key length: " + std::to_string(publicKey.length()));
    cryptoDebugPrint("Private key length: " + std::to_string(privateKey.length()));
    
    return true;
}

// Format raw key as PEM for OpenSSL functions - kept for backward compatibility
// but no longer used in the key generation flow
std::string formatAsPEM(const std::string& rawKey, bool isPrivate) {
    std::string result;
    
    if (isPrivate) {
        result = "-----BEGIN PRIVATE KEY-----\n";
    } else {
        result = "-----BEGIN PUBLIC KEY-----\n";
    }
    
    // Add base64 data in 64-character chunks with line breaks
    for (size_t i = 0; i < rawKey.length(); i += 64) {
        result += rawKey.substr(i, std::min(size_t(64), rawKey.length() - i)) + "\n";
    }
    
    if (isPrivate) {
        result += "-----END PRIVATE KEY-----\n";
    } else {
        result += "-----END PUBLIC KEY-----\n";
    }
    
    return result;
}

// FIXED: Load a private key from PEM format
EVP_PKEY* loadPrivateKeyFromPEM(const std::string& pemKey) {
    cryptoDebugPrint("Loading private key from PEM, length: " + std::to_string(pemKey.length()));
    
    if (pemKey.empty()) {
        cryptoDebugPrint("Empty PEM key provided");
        return NULL;
    }
    
    // Check for PEM format
    if (pemKey.find("-----BEGIN PRIVATE KEY-----") == std::string::npos) {
        cryptoDebugPrint("WARNING: PEM key doesn't have correct header");
    }
    
    BIO* bio = BIO_new_mem_buf(pemKey.c_str(), -1);
    if (!bio) {
        cryptoDebugPrint("Failed to create BIO object for key loading");
        return NULL;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Get OpenSSL error
        unsigned long errCode = ERR_get_error();
        char errBuf[256];
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        cryptoDebugPrint("Failed to load private key: " + std::string(errBuf));
    }
    
    BIO_free(bio);
    
    return pkey;
}

// FIXED: Load a public key from PEM format
EVP_PKEY* loadPublicKeyFromPEM(const std::string& pemKey) {
    cryptoDebugPrint("Loading public key from PEM, length: " + std::to_string(pemKey.length()));
    
    if (pemKey.empty()) {
        cryptoDebugPrint("Empty PEM key provided");
        return NULL;
    }
    
    // Check for PEM format
    if (pemKey.find("-----BEGIN PUBLIC KEY-----") == std::string::npos) {
        cryptoDebugPrint("WARNING: PEM key doesn't have correct header");
    }
    
    BIO* bio = BIO_new_mem_buf(pemKey.c_str(), -1);
    if (!bio) {
        cryptoDebugPrint("Failed to create BIO object for key loading");
        return NULL;
    }
    
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    if (!pkey) {
        // Get OpenSSL error
        unsigned long errCode = ERR_get_error();
        char errBuf[256];
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        cryptoDebugPrint("Failed to load public key: " + std::string(errBuf));
    }
    
    BIO_free(bio);
    
    return pkey;
}

// FIXED: Sign data with RSA private key (now accepts full PEM formatted key)
std::string signData(const std::string& data, const std::string& privateKeyPEM) {
    initOpenSSL();
    
    cryptoDebugPrint("Signing data: \"" + data + "\"");
    cryptoDebugPrint("Private key length: " + std::to_string(privateKeyPEM.length()));
    
    // Load the private key
    EVP_PKEY* pkey = loadPrivateKeyFromPEM(privateKeyPEM);
    if (!pkey) {
        cryptoDebugPrint("Failed to load private key");
        return "";
    }
    
    // Create digest context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        cryptoDebugPrint("Failed to create message digest context");
        EVP_PKEY_free(pkey);
        return "";
    }
    
    // Initialize the signing operation
    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        cryptoDebugPrint("Failed to initialize signing operation");
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // Update with the data to be signed
    if (EVP_DigestSignUpdate(mdctx, data.c_str(), data.size()) != 1) {
        cryptoDebugPrint("Failed during digest update");
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // Get signature length
    size_t slen;
    if (EVP_DigestSignFinal(mdctx, NULL, &slen) != 1) {
        cryptoDebugPrint("Failed to get signature length");
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // Allocate memory for the signature
    std::vector<unsigned char> signature(slen);
    
    // Get the signature
    if (EVP_DigestSignFinal(mdctx, signature.data(), &slen) != 1) {
        cryptoDebugPrint("Failed to create signature");
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return "";
    }
    
    // Clean up
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    
    // Base64 encode the signature
    std::string b64Signature = base64Encode(signature.data(), slen);
    cryptoDebugPrint("Signature generated successfully, length: " + std::to_string(b64Signature.length()));
    
    return b64Signature;
}

// FIXED: Verify signature with RSA public key (now accepts full PEM formatted key)
bool verifySignature(const std::string& data, const std::string& signatureBase64, const std::string& publicKeyPEM) {
    initOpenSSL();
    
    cryptoDebugPrint("Verifying signature for data: \"" + data + "\"");
    cryptoDebugPrint("Signature length: " + std::to_string(signatureBase64.length()));
    cryptoDebugPrint("Public key length: " + std::to_string(publicKeyPEM.length()));
    
    // Load the public key
    EVP_PKEY* pkey = loadPublicKeyFromPEM(publicKeyPEM);
    if (!pkey) {
        cryptoDebugPrint("Failed to load public key");
        return false;
    }
    
    // Decode base64 signature
    std::vector<unsigned char> signature = base64Decode(signatureBase64);
    if (signature.empty()) {
        cryptoDebugPrint("Failed to decode base64 signature");
        EVP_PKEY_free(pkey);
        return false;
    }
    
    cryptoDebugPrint("Decoded signature size: " + std::to_string(signature.size()));
    
    // Create digest context
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        cryptoDebugPrint("Failed to create message digest context");
        EVP_PKEY_free(pkey);
        return false;
    }
    
    // Initialize the verification operation
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        cryptoDebugPrint("Failed to initialize verification operation");
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    
    // Update with the data to verify
    if (EVP_DigestVerifyUpdate(mdctx, data.c_str(), data.size()) != 1) {
        cryptoDebugPrint("Failed during digest update for verification");
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    
    // Verify the signature
    int result = EVP_DigestVerifyFinal(mdctx, signature.data(), signature.size());
    
    if (result != 1) {
        unsigned long errCode = ERR_get_error();
        char errBuf[256];
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        cryptoDebugPrint("Signature verification failed: " + std::string(errBuf));
    } else {
        cryptoDebugPrint("Signature verified successfully");
    }
    
    // Clean up
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(mdctx);
    
    return (result == 1);
}

// Save key to file with binary writing and debugging
bool saveKeyToFile(const std::string& filename, const std::string& key, const std::string& password) {
    // Print debug info
    cryptoDebugPrint("Saving key to file: " + filename);
    cryptoDebugPrint("Key length: " + std::to_string(key.length()));
    
    // Encrypt the key with the password
    std::string encryptedKey = aes256_encrypt(key, sha256(password));
    cryptoDebugPrint("Encrypted key length: " + std::to_string(encryptedKey.length()));
    
    // Write to file in binary mode
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        cryptoDebugPrint("ERROR: Could not open file for writing");
        return false;
    }
    
    file.write(encryptedKey.c_str(), encryptedKey.length());
    file.close();
    
    cryptoDebugPrint("Key saved successfully");
    return true;
}

// Load key from file with complete file reading and debugging
std::string loadKeyFromFile(const std::string& filename, const std::string& password) {
    cryptoDebugPrint("Loading key from file: " + filename);
    
    // Read the entire file content as binary data
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        cryptoDebugPrint("ERROR: Could not open file for reading");
        return "";
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string encryptedKey = buffer.str();
    file.close();
    
    cryptoDebugPrint("Read encrypted key length: " + std::to_string(encryptedKey.length()));
    
    // Decrypt the key with the password
    std::string decryptedKey = aes256_decrypt(encryptedKey, sha256(password));
    
    cryptoDebugPrint("Decrypted key length: " + std::to_string(decryptedKey.length()));
    
    return decryptedKey;
}