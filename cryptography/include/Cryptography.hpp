#pragma once

#include "Key.hpp"
#include "KeystoreStatus.hpp"

using Hash256 = std::array<uint8_t, 32>;

class Cryptography
{
public: 
    Hash256 hashKeySha256(KeyData keyData);
};