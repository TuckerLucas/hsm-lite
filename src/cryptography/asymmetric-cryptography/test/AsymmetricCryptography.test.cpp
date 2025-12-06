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

TEST_CASE("RSA Verify")
{
    AsymmetricCryptography crypto;

    auto rsaKeySize = GENERATE(RsaKeySize::RSA2048, RsaKeySize::RSA4096);

    SECTION("Success")
    {
        auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);

        REQUIRE(keyPair.has_value());

        auto signature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);
        REQUIRE(signature.has_value());

        auto verify =
            crypto.rsaVerify(keyPair->publicKey, TestVectors::plainText, signature.value());

        REQUIRE(verify == true);
    }

    SECTION("Fails on modified message")
    {
        auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);
        REQUIRE(keyPair.has_value());

        auto signature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);
        REQUIRE(signature.has_value());

        std::vector<uint8_t> tamperedPlainText = TestVectors::plainText;
        tamperedPlainText[0] ^= 0xFF;  // flip the first byte

        auto verify = crypto.rsaVerify(keyPair->publicKey, tamperedPlainText, signature.value());
        REQUIRE(verify == false);
    }

    SECTION("Fails with wrong public key")
    {
        auto keyPair1 = crypto.rsaGenerateKeyPair(rsaKeySize);
        auto keyPair2 = crypto.rsaGenerateKeyPair(rsaKeySize);

        REQUIRE(keyPair1.has_value());
        REQUIRE(keyPair2.has_value());

        auto signature = crypto.rsaSign(keyPair1->privateKey, TestVectors::plainText);
        REQUIRE(signature.has_value());

        auto verify =
            crypto.rsaVerify(keyPair2->publicKey, TestVectors::plainText, signature.value());
        REQUIRE(verify == false);
    }

    SECTION("Fails with invalidsignature")
    {
        auto keyPair = crypto.rsaGenerateKeyPair(rsaKeySize);
        REQUIRE(keyPair.has_value());

        auto invalidSignature = crypto.rsaSign(keyPair->privateKey, TestVectors::plainText);
        REQUIRE(invalidSignature.has_value());

        invalidSignature->at(0) ^= 0x01;  // flip the LSB of the first byte

        auto verify =
            crypto.rsaVerify(keyPair->publicKey, TestVectors::plainText, invalidSignature.value());
        REQUIRE(verify == false);
    }
}

TEST_CASE("ECDSA Generate Key Pair")
{
    AsymmetricCryptography crypto;

    SECTION("Success")
    {
        auto ellipticCurve =
            GENERATE(EllipticCurve::SECP256R1, EllipticCurve::SECP384R1, EllipticCurve::SECP521R1);

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

    auto ellipticCurve =
        GENERATE(EllipticCurve::SECP256R1, EllipticCurve::SECP384R1, EllipticCurve::SECP521R1);

    auto keyPair = crypto.ecdsaGenerateKeyPair(ellipticCurve);
    REQUIRE(keyPair.has_value());

    auto signature = crypto.ecdsaSign(keyPair->privateKey, TestVectors::plainText);

    REQUIRE(signature.has_value());
}

TEST_CASE("ECDSA Verify")
{
    AsymmetricCryptography crypto;

    auto ellipticCurve =
        GENERATE(EllipticCurve::SECP256R1, EllipticCurve::SECP384R1, EllipticCurve::SECP521R1);

    SECTION("Success")
    {
        auto keyPair = crypto.ecdsaGenerateKeyPair(ellipticCurve);
        REQUIRE(keyPair.has_value());

        auto signature = crypto.ecdsaSign(keyPair->privateKey, TestVectors::plainText);
        REQUIRE(signature.has_value());

        auto verify =
            crypto.ecdsaVerify(keyPair->publicKey, TestVectors::plainText, signature.value());

        REQUIRE(verify == true);
    }

    SECTION("Fails on modified message")
    {
        auto keyPair = crypto.ecdsaGenerateKeyPair(ellipticCurve);
        REQUIRE(keyPair.has_value());

        auto signature = crypto.ecdsaSign(keyPair->privateKey, TestVectors::plainText);
        REQUIRE(signature.has_value());

        std::vector<uint8_t> tamperedPlainText = TestVectors::plainText;
        tamperedPlainText[0] ^= 0x01;  // flip the LSB of the first byte

        auto verify = crypto.ecdsaVerify(keyPair->publicKey, tamperedPlainText, signature.value());
        REQUIRE(verify == false);
    }

    SECTION("Fails with wrong public key")
    {
        auto keyPair1 = crypto.ecdsaGenerateKeyPair(ellipticCurve);
        auto keyPair2 = crypto.ecdsaGenerateKeyPair(ellipticCurve);

        REQUIRE(keyPair1.has_value());
        REQUIRE(keyPair2.has_value());

        auto signature = crypto.ecdsaSign(keyPair1->privateKey, TestVectors::plainText);
        REQUIRE(signature.has_value());

        auto verify =
            crypto.ecdsaVerify(keyPair2->publicKey, TestVectors::plainText, signature.value());
        REQUIRE(verify == false);
    }

    SECTION("Fails with invalid signature")
    {
        auto keyPair = crypto.ecdsaGenerateKeyPair(ellipticCurve);
        REQUIRE(keyPair.has_value());

        auto invalidSignature = crypto.ecdsaSign(keyPair->privateKey, TestVectors::plainText);
        REQUIRE(invalidSignature.has_value());

        invalidSignature->at(0) ^= 0x01;  // flip the LSB of the first byte

        auto verify = crypto.ecdsaVerify(keyPair->publicKey, TestVectors::plainText,
                                         invalidSignature.value());
        REQUIRE(verify == false);
    }
}