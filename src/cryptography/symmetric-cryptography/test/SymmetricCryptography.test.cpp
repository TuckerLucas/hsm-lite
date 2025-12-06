#include "SymmetricCryptography.hpp"

#include <stdlib.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "TestVectors.hpp"

using namespace std;

TEST_CASE("Encrypt/decrypt success")
{
    SymmetricCryptography crypto;
    Key key{33, {}};

    struct TestData
    {
        KeyData keyData;
        AesKeySize aesKeySize;
        CipherMode aesMode;
        vector<uint8_t> cipherText;
        optional<IV> iv;
    };

    auto testData = GENERATE(TestData{TestVectors::keyData16B, AesKeySize::AES128, CipherMode::ECB,
                                      TestVectors::expectedAes128EcbCipherText},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, CipherMode::CBC,
                                      TestVectors::expectedAes128CbcCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, CipherMode::CTR,
                                      TestVectors::expectedAes128CtrCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, CipherMode::ECB,
                                      TestVectors::expectedAes192EcbCipherText},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, CipherMode::CBC,
                                      TestVectors::expectedAes192CbcCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, CipherMode::CTR,
                                      TestVectors::expectedAes192CtrCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, CipherMode::ECB,
                                      TestVectors::expectedAes256EcbCipherText},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, CipherMode::CBC,
                                      TestVectors::expectedAes256CbcCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, CipherMode::CTR,
                                      TestVectors::expectedAes256CtrCipherText, TestVectors::iv});

    key.data = testData.keyData;

    auto actualCipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize,
                                              testData.aesMode, testData.iv);

    REQUIRE(actualCipherText.has_value());

    REQUIRE(actualCipherText == testData.cipherText);

    auto actualPlainText = crypto.aesDecrypt(key, testData.cipherText, testData.aesKeySize,
                                             testData.aesMode, testData.iv);

    REQUIRE(actualPlainText.has_value());

    REQUIRE(actualPlainText == TestVectors::plainText);
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    SymmetricCryptography crypto;
    Key key{7, TestVectors::keyDataAllZeros};

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256,
                                        CipherMode::ECB, TestVectors::iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid key size fails")
{
    SymmetricCryptography crypto;
    Key key{66, TestVectors::keyData24B};
    uint8_t invalidKeySize = 0xFA;

    auto cipherText =
        crypto.aesEncrypt(key, TestVectors::plainText, static_cast<AesKeySize>(invalidKeySize),
                          CipherMode::ECB, TestVectors::iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid block cipher mode of operation fails")
{
    SymmetricCryptography crypto;
    Key key{250, {}};
    uint8_t invalidMode = 0xFF;

    struct TestData
    {
        KeyData keyData;
        AesKeySize aesKeySize;
    };

    auto testData = GENERATE(TestData{TestVectors::keyData16B, AesKeySize::AES128},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256});

    key.data = testData.keyData;

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize,
                                        static_cast<CipherMode>(invalidMode), TestVectors::iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with incorrect IV size fails")
{
    SymmetricCryptography crypto;
    Key key{233, TestVectors::keyData32B};

    struct TestData
    {
        CipherMode aesMode;
        optional<IV> iv;
    };

    auto testData =
        GENERATE(TestData{CipherMode::ECB, TestVectors::iv}, TestData{CipherMode::CBC, nullopt},
                 TestData{CipherMode::CTR, nullopt});

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128,
                                        testData.aesMode, testData.iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    SymmetricCryptography crypto;
    Key key{76, TestVectors::keyDataAllZeros};

    auto plainText = crypto.aesDecrypt(key, TestVectors::expectedAes256EcbCipherText,
                                       AesKeySize::AES256, CipherMode::ECB, TestVectors::iv);

    REQUIRE_FALSE(plainText.has_value());
}

TEST_CASE("Decrypt cipher text with invalid cipher block mode of operation fails")
{
    SymmetricCryptography crypto;
    Key key{50, TestVectors::keyData32B};
    uint8_t invalidMode = 0xFF;

    auto plainText = crypto.aesDecrypt(key, TestVectors::plainText, AesKeySize::AES256,
                                       static_cast<CipherMode>(invalidMode), TestVectors::iv);

    REQUIRE_FALSE(plainText.has_value());
}