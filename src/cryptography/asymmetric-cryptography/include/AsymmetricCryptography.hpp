#pragma once

#include <optional>

#include "CryptoCommon.hpp"

class AsymmetricCryptography
{
public:
    optional<KeyPair> rsaGenerateKeyPair();
};