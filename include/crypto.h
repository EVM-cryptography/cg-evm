#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>

// Computes the SHA256 hash of the input string and returns its hex string.
std::string sha256(const std::string &input);

// Encrypts plaintext using AES256-CBC with the provided key (as a hex string).
// Returns the ciphertext as a hex string.
std::string aes256_encrypt(const std::string &plaintext, const std::string &key);

// Decrypts a hex-encoded ciphertext using AES256-CBC with the provided key (as a hex string).
std::string aes256_decrypt(const std::string &ciphertext, const std::string &key);

#endif