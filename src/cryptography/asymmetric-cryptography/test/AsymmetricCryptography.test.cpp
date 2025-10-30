#include <stdlib.h>

#include <catch2/catch_test_macros.hpp>

#include "AsymmetricCryptography.hpp"

TEST_CASE("Generate key pair succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.rsaGenerateKeyPair();

    auto priv = keyPair->privateKey.data;
    auto pub = keyPair->publicKey.data;

    REQUIRE(keyPair.has_value());
    REQUIRE_FALSE(priv.empty());
    REQUIRE_FALSE(pub.empty());

    REQUIRE(std::string(priv.begin(), priv.begin() + 27) == "-----BEGIN PRIVATE KEY-----");
    REQUIRE(std::string(pub.begin(), pub.begin() + 26) == "-----BEGIN PUBLIC KEY-----");
}