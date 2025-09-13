#include <catch2/catch_test_macros.hpp>

#include "Cryptography.hpp"

TEST_CASE("Hash key successful")
{
    Cryptography crypto;
    KeyData keyData = {0x12, 0x11, 0xAD, 0xB1, 0xFD, 0x44, 0x66, 0x00, 0x19};

    //auto keyHash = crypto.hashKey(keyData);
}