#pragma once

#include "CryptoCommon.hpp"
#include "Key.hpp"
#include "StatusCode.hpp"

#include <memory>
#include <vector>
#include <array>
#include <optional>
#include <openssl/evp.h>
#include <openssl/sha.h>

class Cryptography
{
public: 
    optional<vector<uint8_t>> hashKey(Key key, HashAlgorithm hashAlgorithm);

    optional<vector<uint8_t>> aes256Encrypt(const Key& key, const vector<uint8_t>& plainText, AesMode aesMode);

    optional<vector<uint8_t>> aes256Decrypt(const Key& key, const vector<uint8_t>& cipherText, AesMode aesMode);
private:
    optional<vector<uint8_t>> aes256Crypt(const Key& key, const vector<uint8_t>& input, AesMode aesMode, CipherOperation cipherOperation);
};