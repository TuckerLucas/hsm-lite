#pragma once

#include "Key.hpp"
#include "StatusCode.hpp"

#include <optional>
#include <openssl/evp.h>
#include <openssl/sha.h>

using Hash256 = std::array<uint8_t, 32>;

class Cryptography
{
public: 
    optional<Hash256> hashKeySha256(Key key);

    optional<array<std::uint8_t, 32U>> aes256Encrypt(Key key, std::array<uint8_t, 32> plainText);
};