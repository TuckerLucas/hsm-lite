#include "Cryptography.hpp"
#include "TestVectors.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <stdlib.h>

using namespace std;

TEST_CASE("Hash key successful")
{
    Cryptography crypto;
    Key key1{1, TestVectors::keyData32B};

    struct TestData
    {
        HashAlgorithm hashAlgo;
        vector<uint8_t> expectedHash;
    };

    auto testData = GENERATE(TestData{HashAlgorithm::SHA224, TestVectors::expectedSha224Hash_keyData32B},
                             TestData{HashAlgorithm::SHA256, TestVectors::expectedSha256Hash_keyData32B},
                             TestData{HashAlgorithm::SHA384, TestVectors::expectedSha384Hash_keyData32B},
                             TestData{HashAlgorithm::SHA512, TestVectors::expectedSha512Hash_keyData32B});

    auto actualHash = crypto.hashKey(key1, testData.hashAlgo);

    REQUIRE(actualHash.has_value());

    REQUIRE(actualHash == testData.expectedHash);
}

TEST_CASE("Hash all zero key fails")
{
    Cryptography crypto;
    Key key{28, TestVectors::keyDataAllZeros};

    auto actualHashKeyData = crypto.hashKey(key, HashAlgorithm::SHA256);

    REQUIRE_FALSE(actualHashKeyData.has_value());
}

TEST_CASE("Hash key with invalid algorithm fails")
{
    Cryptography crypto;
    Key key{200, TestVectors::keyData32B};
    uint8_t invalidHashAlgorithm = 0xFF;

    auto actualHashKeyData = crypto.hashKey(key, static_cast<HashAlgorithm>(invalidHashAlgorithm));

    REQUIRE_FALSE(actualHashKeyData.has_value());
}

TEST_CASE("Encrypt/decrypt success")
{
    Cryptography crypto;
    Key key{33, {}};

    struct TestData 
    {
        KeyData keyData;
        vector<uint8_t> cipherText;
        AesKeySize aesKeySize;
        AesMode aesMode;
        optional<IV> iv;
    };

    auto testData = GENERATE(TestData{TestVectors::keyData16B, TestVectors::expectedAes128EcbCipherText, AesKeySize::AES128, AesMode::ECB},
                             TestData{TestVectors::keyData16B, TestVectors::expectedAes128CbcCipherText, AesKeySize::AES128, AesMode::CBC, TestVectors::iv},
                             TestData{TestVectors::keyData16B, TestVectors::expectedAes128CtrCipherText, AesKeySize::AES128, AesMode::CTR, TestVectors::iv},
                             TestData{TestVectors::keyData24B, TestVectors::expectedAes192EcbCipherText, AesKeySize::AES192, AesMode::ECB},
                             TestData{TestVectors::keyData24B, TestVectors::expectedAes192CbcCipherText, AesKeySize::AES192, AesMode::CBC, TestVectors::iv},
                             TestData{TestVectors::keyData24B, TestVectors::expectedAes192CtrCipherText, AesKeySize::AES192, AesMode::CTR, TestVectors::iv},
                             TestData{TestVectors::keyData32B, TestVectors::expectedAes256EcbCipherText, AesKeySize::AES256, AesMode::ECB},
                             TestData{TestVectors::keyData32B, TestVectors::expectedAes256CbcCipherText, AesKeySize::AES256, AesMode::CBC, TestVectors::iv},
                             TestData{TestVectors::keyData32B, TestVectors::expectedAes256CtrCipherText, AesKeySize::AES256, AesMode::CTR, TestVectors::iv});

    key.data = testData.keyData;
    
    auto actualCipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize, testData.aesMode, testData.iv);

    REQUIRE(actualCipherText.has_value());

    REQUIRE(actualCipherText == testData.cipherText);

    auto actualPlainText = crypto.aesDecrypt(key, testData.cipherText, testData.aesKeySize, testData.aesMode, testData.iv);

    REQUIRE(actualPlainText.has_value());

    REQUIRE(actualPlainText == TestVectors::plainText);
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    Cryptography crypto;
    Key key{7, TestVectors::keyDataAllZeros};

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::ECB, TestVectors::iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid key size fails")
{
    Cryptography crypto;
    Key key{66, TestVectors::keyData24B};
    uint8_t invalidKeySize = 0xFA;

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, static_cast<AesKeySize>(invalidKeySize), AesMode::ECB, TestVectors::iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid block cipher mode of operation fails")
{
    Cryptography crypto;
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

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize, static_cast<AesMode>(invalidMode), TestVectors::iv);
    
    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with incorrect IV size fails")
{
    Cryptography crypto;
    Key key{233, TestVectors::keyData32B};

    struct TestData
    {
        AesMode aesMode;
        optional<IV> iv;
    };

    auto testData = GENERATE(TestData{AesMode::ECB, TestVectors::iv},
                             TestData{AesMode::CBC, nullopt},
                             TestData{AesMode::CTR, nullopt});

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128, testData.aesMode, testData.iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyDataAllZeros};

    auto plainText = crypto.aesDecrypt(key, TestVectors::expectedAes256EcbCipherText, AesKeySize::AES256, AesMode::ECB, TestVectors::iv);

    REQUIRE_FALSE(plainText.has_value());
}

TEST_CASE("Decrypt cipher text with invalid cipher block mode of operation fails")
{
    Cryptography crypto;
    Key key{50, TestVectors::keyData32B};
    uint8_t invalidMode = 0xFF;

    auto plainText = crypto.aesDecrypt(key, TestVectors::plainText, AesKeySize::AES256, static_cast<AesMode>(invalidMode), TestVectors::iv);

    REQUIRE_FALSE(plainText.has_value());
}