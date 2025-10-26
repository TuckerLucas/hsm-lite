#include "Cryptography.hpp"
#include "TestVectors.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>
#include <stdlib.h>

using namespace std;

TEST_CASE("Hash key successful")
{
    Cryptography crypto;
    Key key1{1, TestVectors::keyData1};

    struct TestData
    {
        HashAlgorithm hashAlgo;
        vector<uint8_t> expectedHash;
    };

    auto testData = GENERATE(TestData{HashAlgorithm::SHA224, TestVectors::expectedSha224Hash_KeyData1},
                             TestData{HashAlgorithm::SHA256, TestVectors::expectedSha256Hash_KeyData1},
                             TestData{HashAlgorithm::SHA384, TestVectors::expectedSha384Hash_KeyData1},
                             TestData{HashAlgorithm::SHA512, TestVectors::expectedSha512Hash_KeyData1});

    auto actualHash = crypto.hashKey(key1, testData.hashAlgo);

    REQUIRE(actualHash.has_value());

    REQUIRE(actualHash == testData.expectedHash);
}

TEST_CASE("Hash all zero key fails")
{
    Cryptography crypto;
    Key key{28, TestVectors::allZeroKeyData};

    auto actualHashKeyData = crypto.hashKey(key, HashAlgorithm::SHA256);

    REQUIRE_FALSE(actualHashKeyData.has_value());
}

TEST_CASE("Hash key with invalid algorithm fails")
{
    Cryptography crypto;
    Key key{200, TestVectors::keyData1};
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
    };

    auto testData = GENERATE(TestData{TestVectors::keyData3, TestVectors::expectedAes128EcbCipherText_KeyData3, AesKeySize::AES128, AesMode::ECB},
                             TestData{TestVectors::keyData3, TestVectors::expectedAes128CbcCipherText_KeyData3, AesKeySize::AES128, AesMode::CBC},
                             TestData{TestVectors::keyData3, TestVectors::expectedAes128CtrCipherText_KeyData3, AesKeySize::AES128, AesMode::CTR},
                             TestData{TestVectors::keyData4, TestVectors::expectedAes192EcbCipherText_KeyData4, AesKeySize::AES192, AesMode::ECB},
                             TestData{TestVectors::keyData4, TestVectors::expectedAes192CbcCipherText_KeyData4, AesKeySize::AES192, AesMode::CBC},
                             TestData{TestVectors::keyData4, TestVectors::expectedAes192CtrCipherText_KeyData4, AesKeySize::AES192, AesMode::CTR},
                             TestData{TestVectors::keyData, TestVectors::expectedAes256EcbCipherText_KeyData, AesKeySize::AES256, AesMode::ECB},
                             TestData{TestVectors::keyData, TestVectors::expectedAes256CbcCipherText_KeyData, AesKeySize::AES256, AesMode::CBC},
                             TestData{TestVectors::keyData, TestVectors::expectedAes256CtrCipherText_KeyData, AesKeySize::AES256, AesMode::CTR});

    key.data = testData.keyData;

    auto actualCipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize, testData.aesMode, TestVectors::iv_all_ones);

    REQUIRE(actualCipherText.has_value());

    REQUIRE(actualCipherText == testData.cipherText);

    auto actualPlainText = crypto.aesDecrypt(key, testData.cipherText, testData.aesKeySize, testData.aesMode, TestVectors::iv_all_ones);

    REQUIRE(actualPlainText.has_value());

    REQUIRE(actualPlainText == TestVectors::plainText);
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    Cryptography crypto;
    Key key{7, TestVectors::allZeroKeyData};

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_zeros);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid key size fails")
{
    Cryptography crypto;
    Key key{66, TestVectors::keyData4};
    uint8_t invalidKeySize = 0xFA;

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, static_cast<AesKeySize>(invalidKeySize), AesMode::ECB, TestVectors::iv_all_zeros);

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

    auto testData = GENERATE(TestData{TestVectors::keyData3, AesKeySize::AES128},
                             TestData{TestVectors::keyData4, AesKeySize::AES192},
                             TestData{TestVectors::keyData, AesKeySize::AES256});

    key.data = testData.keyData;

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize, static_cast<AesMode>(invalidMode), TestVectors::iv_all_zeros);
    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::allZeroKeyData};

    auto plainText = crypto.aesDecrypt(key, TestVectors::expectedAes256EcbCipherText_KeyData, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_zeros);

    REQUIRE_FALSE(plainText.has_value());
}

TEST_CASE("Decrypt cipher text with invalid cipher block mode of operation fails")
{
    Cryptography crypto;
    Key key{50, TestVectors::keyData};
    uint8_t invalidMode = 0xFF;

    auto plainText = crypto.aesDecrypt(key, TestVectors::plainText, AesKeySize::AES256, static_cast<AesMode>(invalidMode), TestVectors::iv_all_zeros);

    REQUIRE_FALSE(plainText.has_value());
}