#pragma once

#include <array>
#include <cstdint>

using namespace std;

using IV = array<uint8_t, 16>;

enum class HashAlgorithm
{
    SHA224,
    SHA256,
    SHA384,
    SHA512
};

enum class AesKeySize
{
    AES128 = 128,
    AES192 = 192,
    AES256 = 256
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