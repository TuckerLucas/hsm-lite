#pragma once

#include "Key.hpp"
#include "StatusCode.hpp"

#include <vector>
#include <array>
#include <optional>
#include <openssl/evp.h>
#include <openssl/sha.h>

enum class HashAlgorithm
{
    SHA256,
    SHA512
};

class Cryptography
{
public: 
    optional<vector<uint8_t>> hashKey(Key key, HashAlgorithm hashAlgorithm);

    optional<vector<uint8_t>> aes256Encrypt(const Key& key, const vector<uint8_t>& plainText);

    optional<vector<uint8_t>> aes256Decrypt(const Key& key, const vector<uint8_t>& cipherText);
};