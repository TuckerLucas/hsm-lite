#pragma once

#include <optional>

#include "CryptoCommon.hpp"

class AsymmetricCryptography
{
public:
    optional<KeyPair> rsaGenerateKeyPair();

    optional<std::vector<uint8_t>> rsaEncrypt(const Key& key, const vector<uint8_t>& input);
};