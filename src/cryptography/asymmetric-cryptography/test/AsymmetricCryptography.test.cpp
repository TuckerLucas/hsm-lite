#include "AsymmetricCryptography.hpp"

#include <stdlib.h>

#include <catch2/catch_test_macros.hpp>

#include "TestVectors.hpp"

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

TEST_CASE("Encryption succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.rsaGenerateKeyPair();
    REQUIRE(keyPair.has_value());

    auto cipherText = crypto.rsaEncrypt(keyPair->publicKey, TestVectors::plainText);

    REQUIRE(cipherText.has_value());
    REQUIRE(cipherText->size() == 256);
}

TEST_CASE("Decryption succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.rsaGenerateKeyPair();

    REQUIRE(keyPair.has_value());

    auto cipherText = crypto.rsaEncrypt(keyPair->publicKey, TestVectors::plainText);

    REQUIRE(cipherText.has_value());

    auto plainText = crypto.rsaDecrypt(keyPair->privateKey, cipherText.value());

    REQUIRE(plainText.has_value());
    REQUIRE(plainText->size() == 32);
    REQUIRE(plainText.value() == TestVectors::plainText);
}

TEST_CASE("Sign succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.rsaGenerateKeyPair();

    REQUIRE(keyPair.has_value());

    auto signature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);

    REQUIRE(signature.has_value());
    REQUIRE(signature->size() == 256);
}

TEST_CASE("Verifying succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.rsaGenerateKeyPair();

    REQUIRE(keyPair.has_value());

    auto signature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);

    REQUIRE(signature.has_value());

    auto verify = crypto.rsaVerify(keyPair->publicKey, TestVectors::plainText, signature.value());

    REQUIRE(verify);
}