#include "AsymmetricCryptography.hpp"

#include <stdlib.h>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("Generate key pair succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.rsaGenerateKeyPair();

    REQUIRE(keyPair.has_value());
    REQUIRE_FALSE(keyPair->privateKey.data.empty());
    REQUIRE_FALSE(keyPair->publicKey.data.empty());

    REQUIRE(std::string(keyPair->privateKey.data.begin(), keyPair->privateKey.data.begin() + 27) ==
            "-----BEGIN PRIVATE KEY-----");
    REQUIRE(std::string(keyPair->publicKey.data.begin(), keyPair->publicKey.data.begin() + 26) ==
            "-----BEGIN PUBLIC KEY-----");

    REQUIRE(keyPair->privateKey.id == 0U);
    REQUIRE(keyPair->publicKey.id == 0U);
}