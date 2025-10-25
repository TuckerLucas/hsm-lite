#pragma once

#include <array>

using namespace std;

using IV = array<uint8_t, 16>;

enum class HashAlgorithm
{
    SHA224,
    SHA256,
    SHA384,
    SHA512
};

enum class AesMode
{
    ECB,
    CBC,
    CTR
};

enum class CipherOperation
{
    Encrypt,
    Decrypt
};