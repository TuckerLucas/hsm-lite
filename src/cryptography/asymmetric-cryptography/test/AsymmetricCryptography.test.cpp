#include "AsymmetricCryptography.hpp"

#include <stdlib.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "TestVectors.hpp"

TEST_CASE("RSA Generate key pair")
{
    AsymmetricCryptography crypto;

    SECTION("Success")
    {
        auto rsaKeySize = GENERATE(RsaKeySize::RSA2048, RsaKeySize::RSA4096);

        auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);

        REQUIRE(keyPair.has_value());
        REQUIRE_FALSE(keyPair->privateKey.data.empty());
        REQUIRE_FALSE(keyPair->publicKey.data.empty());

        REQUIRE(
            std::string(keyPair->privateKey.data.begin(), keyPair->privateKey.data.begin() + 27) ==
            "-----BEGIN PRIVATE KEY-----");
        REQUIRE(std::string(keyPair->publicKey.data.begin(),
                            keyPair->publicKey.data.begin() + 26) == "-----BEGIN PUBLIC KEY-----");

        REQUIRE(keyPair->privateKey.id == 0U);
        REQUIRE(keyPair->publicKey.id == 0U);
    }
    SECTION("Invalid key size")
    {
        auto rsaKeySize = static_cast<RsaKeySize>(0xff);

        auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);

        REQUIRE_FALSE(keyPair.has_value());
    }
}

TEST_CASE("RSA Encryption succeeds")
{
    AsymmetricCryptography crypto;

    struct TestData
    {
        RsaKeySize rsaKeySize;
        uint16_t expectedCipherTextSize;
    };

    auto testData =
        GENERATE(TestData{RsaKeySize::RSA2048, 256U}, TestData{RsaKeySize::RSA4096, 512U});

    auto keyPair = crypto.rsaGenerateKeyPair(testData.rsaKeySize);
    REQUIRE(keyPair.has_value());

    auto cipherText = crypto.rsaEncrypt(keyPair->publicKey, TestVectors::plainText);

    REQUIRE(cipherText.has_value());
    REQUIRE(cipherText->size() == testData.expectedCipherTextSize);
}

TEST_CASE("RSA Decryption succeeds")
{
    AsymmetricCryptography crypto;

    struct TestData
    {
        RsaKeySize rsaKeySize;
        uint16_t expectedPlainTextSize;
    };

    auto rsaKeySize = GENERATE(RsaKeySize::RSA2048, RsaKeySize::RSA4096);

    auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);

    REQUIRE(keyPair.has_value());

    auto cipherText = crypto.rsaEncrypt(keyPair->publicKey, TestVectors::plainText);

    REQUIRE(cipherText.has_value());

    auto plainText = crypto.rsaDecrypt(keyPair->privateKey, cipherText.value());

    REQUIRE(plainText.has_value());
    REQUIRE(plainText->size() == 32);
    REQUIRE(plainText.value() == TestVectors::plainText);
}

TEST_CASE("RSA Sign succeeds")
{
    AsymmetricCryptography crypto;

    struct TestData
    {
        RsaKeySize rsaKeySize;
        uint16_t expectedSignatureSize;
    };

    auto testData =
        GENERATE(TestData{RsaKeySize::RSA2048, 256U}, TestData{RsaKeySize::RSA4096, 512U});

    auto keyPair = crypto.rsaGenerateKeyPair(testData.rsaKeySize);

    REQUIRE(keyPair.has_value());

    auto signature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);

    REQUIRE(signature.has_value());
    REQUIRE(signature->size() == testData.expectedSignatureSize);
}

TEST_CASE("RSA Verifying succeeds")
{
    AsymmetricCryptography crypto;

    auto rsaKeySize = GENERATE(RsaKeySize::RSA2048, RsaKeySize::RSA4096);

    auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);

    REQUIRE(keyPair.has_value());

    auto signature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);

    REQUIRE(signature.has_value());

    auto verify = crypto.rsaVerify(keyPair->publicKey, TestVectors::plainText, signature.value());

    REQUIRE(verify);
}

TEST_CASE("ECDSA Generate Key Pair")
{
    AsymmetricCryptography crypto;

    SECTION("SUCCESS")
    {
        auto ellipticCurve = GENERATE(EllipticCurve::SECP256R1, EllipticCurve::SECP384R1);

        auto keyPair = crypto.ecdsaGenerateKeyPair(ellipticCurve);

        REQUIRE(keyPair.has_value());
        REQUIRE_FALSE(keyPair->privateKey.data.empty());
        REQUIRE_FALSE(keyPair->publicKey.data.empty());
        REQUIRE(
            std::string(keyPair->privateKey.data.begin(), keyPair->privateKey.data.begin() + 27) ==
            "-----BEGIN PRIVATE KEY-----");
        REQUIRE(std::string(keyPair->publicKey.data.begin(),
                            keyPair->publicKey.data.begin() + 26) == "-----BEGIN PUBLIC KEY-----");

        REQUIRE(keyPair->privateKey.id == 0U);
        REQUIRE(keyPair->publicKey.id == 0U);
    }
    SECTION("Invalid elliptic curve")
    {
        auto ellipticCurve = static_cast<EllipticCurve>(0xff);

        auto keyPair = crypto.ecdsaGenerateKeyPair(ellipticCurve);

        REQUIRE_FALSE(keyPair.has_value());
    }
}

TEST_CASE("ECDSA Sign succeeds")
{
    AsymmetricCryptography crypto;

    auto keyPair = crypto.ecdsaGenerateKeyPair(EllipticCurve::SECP256R1);
}
