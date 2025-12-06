#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <memory>
#include <optional>
#include <vector>

#include "CryptoCommon.hpp"
#include "Key.hpp"
#include "StatusCode.hpp"

class SymmetricCryptography
{
public:
    optional<vector<uint8_t>> aesEncrypt(const Key& key, const vector<uint8_t>& plainText,
                                         AesKeySize aesKeySize, CipherMode aesMode,
                                         optional<IV> iv = nullopt);

    optional<vector<uint8_t>> aesDecrypt(const Key& key, const vector<uint8_t>& cipherText,
                                         AesKeySize aesKeySize, CipherMode aesMode,
                                         optional<IV> iv = nullopt);

private:
    optional<vector<uint8_t>> aesCrypt(const Key& key, const vector<uint8_t>& input,
                                       AesKeySize aeskeySize, CipherMode aesMode,
                                       CipherOperation cipherOperation, optional<IV> iv);
};