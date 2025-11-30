#pragma once

#include <optional>

#include "CryptoCommon.hpp"

class AsymmetricCryptography
{
public:
    optional<KeyPair> rsaGenerateKeyPair();

    optional<std::vector<uint8_t>> rsaEncrypt(const Key& publicKey,
                                              const vector<uint8_t>& plainText);

    optional<std::vector<uint8_t>> rsaDecrypt(const Key& privateKey,
                                              const vector<uint8_t>& cipherText);
};