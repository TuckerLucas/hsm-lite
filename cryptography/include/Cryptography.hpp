#pragma once

#include "Key.hpp"
#include "KeystoreStatus.hpp"

#include <optional>

using Hash256 = std::array<uint8_t, 32>;

class Cryptography
{
public: 
    optional<Hash256> hashKeySha256(Key key);
};