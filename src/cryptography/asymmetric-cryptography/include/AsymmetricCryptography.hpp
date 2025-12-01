#pragma once

#include <optional>

#include "CryptoCommon.hpp"

class AsymmetricCryptography
{
public:
    optional<KeyPair> rsaGenerateKeyPair(RsaKeySize rsaKeySize);

    optional<vector<uint8_t>> rsaEncrypt(const Key& publicKey, const vector<uint8_t>& plainText);

    optional<vector<uint8_t>> rsaDecrypt(const Key& privateKey, const vector<uint8_t>& cipherText);

    optional<vector<uint8_t>> rsaSign(const Key& privateKey, const vector<uint8_t>& plainText);

    bool rsaVerify(const Key& publicKey, const vector<uint8_t>& plainText,
                   const vector<uint8_t>& signature);
};