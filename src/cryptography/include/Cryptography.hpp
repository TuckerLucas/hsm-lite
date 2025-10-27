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

    optional<vector<uint8_t>> aesEncrypt(const Key& key, const vector<uint8_t>& plainText, AesKeySize aesKeySize, AesMode aesMode, PaddingMode paddingMode, optional<IV> iv = nullopt);

    optional<vector<uint8_t>> aesDecrypt(const Key& key, const vector<uint8_t>& cipherText, AesKeySize aesKeySize, AesMode aesMode, PaddingMode paddingMode, optional<IV> iv = nullopt);
private:
    optional<vector<uint8_t>> aesCrypt(const Key& key, const vector<uint8_t>& input, AesKeySize aeskeySize, AesMode aesMode, PaddingMode paddingMode, CipherOperation cipherOperation, optional<IV> iv);
};