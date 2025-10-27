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
        AesKeySize aesKeySize;
        AesMode aesMode;
        PaddingMode paddingMode;
        vector<uint8_t> cipherText;
        optional<IV> iv;
    };

    auto testData = GENERATE(TestData{TestVectors::keyData16B, AesKeySize::AES128, AesMode::ECB, PaddingMode::None, TestVectors::expectedAes128EcbCipherText},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, AesMode::ECB, PaddingMode::PKCS7, TestVectors::expectedAes128EcbCipherTextPkcs7},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, AesMode::CBC, PaddingMode::None, TestVectors::expectedAes128CbcCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, AesMode::CBC, PaddingMode::PKCS7, TestVectors::expectedAes128CbcCipherTextPkcs7, TestVectors::iv},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, AesMode::CTR, PaddingMode::None, TestVectors::expectedAes128CtrCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData16B, AesKeySize::AES128, AesMode::CTR, PaddingMode::PKCS7, TestVectors::expectedAes128CtrCipherTextPkcs7, TestVectors::iv},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, AesMode::ECB, PaddingMode::None, TestVectors::expectedAes192EcbCipherText},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, AesMode::ECB, PaddingMode::PKCS7, TestVectors::expectedAes192EcbCipherTextPkcs7},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, AesMode::CBC, PaddingMode::None, TestVectors::expectedAes192CbcCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, AesMode::CBC, PaddingMode::PKCS7, TestVectors::expectedAes192CbcCipherTextPkcs7, TestVectors::iv},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, AesMode::CTR, PaddingMode::None, TestVectors::expectedAes192CtrCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData24B, AesKeySize::AES192, AesMode::CTR, PaddingMode::PKCS7, TestVectors::expectedAes192CtrCipherTextPkcs7, TestVectors::iv},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, AesMode::ECB, PaddingMode::None, TestVectors::expectedAes256EcbCipherText},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, AesMode::ECB, PaddingMode::PKCS7, TestVectors::expectedAes256EcbCipherTextPkcs7},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, AesMode::CBC, PaddingMode::None, TestVectors::expectedAes256CbcCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, AesMode::CBC, PaddingMode::PKCS7, TestVectors::expectedAes256CbcCipherTextPkcs7, TestVectors::iv},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, AesMode::CTR, PaddingMode::None, TestVectors::expectedAes256CtrCipherText, TestVectors::iv},
                             TestData{TestVectors::keyData32B, AesKeySize::AES256, AesMode::CTR, PaddingMode::PKCS7, TestVectors::expectedAes256CtrCipherTextPkcs7, TestVectors::iv});

    key.data = testData.keyData;

    auto actualCipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize, testData.aesMode, testData.paddingMode, testData.iv);

    REQUIRE(actualCipherText.has_value());

    REQUIRE(actualCipherText == testData.cipherText);

    auto actualPlainText = crypto.aesDecrypt(key, testData.cipherText, testData.aesKeySize, testData.aesMode, testData.paddingMode, testData.iv);

    REQUIRE(actualPlainText.has_value());

    REQUIRE(actualPlainText == TestVectors::plainText);
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    Cryptography crypto;
    Key key{7, TestVectors::keyDataAllZeros};

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::ECB, PaddingMode::None, TestVectors::iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid key size fails")
{
    Cryptography crypto;
    Key key{66, TestVectors::keyData24B};
    uint8_t invalidKeySize = 0xFA;

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, static_cast<AesKeySize>(invalidKeySize), AesMode::ECB, PaddingMode::None, TestVectors::iv);

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

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, testData.aesKeySize, static_cast<AesMode>(invalidMode), PaddingMode::None, TestVectors::iv);
    
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

    auto cipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128, testData.aesMode, PaddingMode::None, testData.iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyDataAllZeros};

    auto plainText = crypto.aesDecrypt(key, TestVectors::expectedAes256EcbCipherText, AesKeySize::AES256, AesMode::ECB, PaddingMode::None, TestVectors::iv);

    REQUIRE_FALSE(plainText.has_value());
}

TEST_CASE("Decrypt cipher text with invalid cipher block mode of operation fails")
{
    Cryptography crypto;
    Key key{50, TestVectors::keyData32B};
    uint8_t invalidMode = 0xFF;

    auto plainText = crypto.aesDecrypt(key, TestVectors::plainText, AesKeySize::AES256, static_cast<AesMode>(invalidMode), PaddingMode::None, TestVectors::iv);

    REQUIRE_FALSE(plainText.has_value());
}