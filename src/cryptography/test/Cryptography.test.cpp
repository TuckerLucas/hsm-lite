#include "Cryptography.hpp"
#include "TestVectors.hpp"

#include <catch2/catch_test_macros.hpp>
#include <stdlib.h>

using namespace std;

TEST_CASE("Hash key successful")
{
    Cryptography crypto;
    Key key1{1, TestVectors::keyData1};
    Key key2{2, TestVectors::keyData2};
    
    SECTION("SHA224")
    {
        auto actualSha224Hash_KeyData1 = crypto.hashKey(key1, HashAlgorithm::SHA224);
        auto actualSha224Hash_KeyData2 = crypto.hashKey(key2, HashAlgorithm::SHA224);

        REQUIRE(actualSha224Hash_KeyData1.has_value());
        REQUIRE(actualSha224Hash_KeyData2.has_value());

        REQUIRE(actualSha224Hash_KeyData1 == TestVectors::expectedSha224Hash_KeyData1);
        REQUIRE(actualSha224Hash_KeyData2 == TestVectors::expectedSha224Hash_KeyData2);
    }

    SECTION("SHA256")
    {
        auto actualSha256Hash_KeyData1 = crypto.hashKey(key1, HashAlgorithm::SHA256);
        auto actualSha256Hash_KeyData2 = crypto.hashKey(key2, HashAlgorithm::SHA256);

        REQUIRE(actualSha256Hash_KeyData1.has_value());
        REQUIRE(actualSha256Hash_KeyData2.has_value());

        REQUIRE(actualSha256Hash_KeyData1 == TestVectors::expectedSha256Hash_KeyData1);
        REQUIRE(actualSha256Hash_KeyData2 == TestVectors::expectedSha256Hash_KeyData2);
    }

    SECTION("SHA384")
    {
        auto actualSha384Hash_KeyData1 = crypto.hashKey(key1, HashAlgorithm::SHA384);
        auto actualSha384Hash_KeyData2 = crypto.hashKey(key2, HashAlgorithm::SHA384);

        REQUIRE(actualSha384Hash_KeyData1.has_value());
        REQUIRE(actualSha384Hash_KeyData2.has_value());

        REQUIRE(actualSha384Hash_KeyData1 == TestVectors::expectedSha384Hash_KeyData1);
        REQUIRE(actualSha384Hash_KeyData2 == TestVectors::expectedSha384Hash_KeyData2);
    }

    SECTION("SHA512")
    {
        auto actualSha512Hash_KeyData1 = crypto.hashKey(key1, HashAlgorithm::SHA512);
        auto actualSha512Hash_KeyData2 = crypto.hashKey(key2, HashAlgorithm::SHA512);

        REQUIRE(actualSha512Hash_KeyData1.has_value());
        REQUIRE(actualSha512Hash_KeyData2.has_value());

        REQUIRE(actualSha512Hash_KeyData1 == TestVectors::expectedSha512Hash_KeyData1);
        REQUIRE(actualSha512Hash_KeyData2 == TestVectors::expectedSha512Hash_KeyData2);
    }
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

TEST_CASE("Encrypt plain text successful - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyData};
    Key key1{36, TestVectors::keyData1};
    auto iv = vector<uint8_t>(16, 0x11);

    SECTION("ECB Mode")
    {
        auto actualAes256EcbCipherText_KeyData = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::ECB, iv);
        auto actualAes256EcbCipherText_KeyData1 = crypto.aes256Encrypt(key1, TestVectors::plainText, AesMode::ECB, iv);

        REQUIRE(actualAes256EcbCipherText_KeyData.has_value());
        REQUIRE(actualAes256EcbCipherText_KeyData1.has_value());

        REQUIRE(actualAes256EcbCipherText_KeyData == TestVectors::expectedAes256EcbCipherText_KeyData);
        REQUIRE(actualAes256EcbCipherText_KeyData1 == TestVectors::expectedAes256EcbCipherText_KeyData1);
    }

    SECTION("CBC Mode")
    {
        auto actualAes256CbcCipherText_KeyData = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::CBC, iv);
        auto actualAes256CbcCipherText_KeyData1 = crypto.aes256Encrypt(key1, TestVectors::plainText, AesMode::CBC, iv);
        
        REQUIRE(actualAes256CbcCipherText_KeyData.has_value());
        REQUIRE(actualAes256CbcCipherText_KeyData1.has_value());

        REQUIRE(actualAes256CbcCipherText_KeyData == TestVectors::expectedAes256CbcCipherText_KeyData);
        REQUIRE(actualAes256CbcCipherText_KeyData1 == TestVectors::expectedAes256CbcCipherText_KeyData1);        
    }

    SECTION("CTR Mode")
    {
        auto actualAes256CtrCipherText_KeyData = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::CTR, iv);
        auto actualAes256CtrCipherText_KeyData1 = crypto.aes256Encrypt(key1, TestVectors::plainText, AesMode::CTR, iv);

        REQUIRE(actualAes256CtrCipherText_KeyData.has_value());
        REQUIRE(actualAes256CtrCipherText_KeyData1.has_value()); 
        
        REQUIRE(actualAes256CtrCipherText_KeyData == TestVectors::expectedAes256CtrCipherText_KeyData);
        REQUIRE(actualAes256CtrCipherText_KeyData1 == TestVectors::expectedAes256CtrCipherText_KeyData1); 
    }
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    Cryptography crypto;
    Key key{7, TestVectors::allZeroKeyData};
    auto iv = vector<uint8_t>(16, 0x00);

    auto cipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::ECB, iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Encrypt plain text with invalid block cipher mode of operation fails")
{
    Cryptography crypto;
    Key key{250, TestVectors::keyData};
    uint8_t invalidMode = 0xFF;
    auto iv = vector<uint8_t>(16, 0x00);

    auto cipherText = crypto.aes256Encrypt(key, TestVectors::plainText, static_cast<AesMode>(invalidMode), iv);

    REQUIRE_FALSE(cipherText.has_value());
}

TEST_CASE("Decrypt cipher text successful - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyData};
    Key key1{88, TestVectors::keyData1};
    auto iv = vector<uint8_t>(16, 0x11);

    SECTION("ECB Mode")
    {
        auto actualAes256EcbPlainText_KeyData = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText_KeyData, AesMode::ECB, iv);
        auto actualAes256EcbPlainText_KeyData1 = crypto.aes256Decrypt(key1, TestVectors::expectedAes256EcbCipherText_KeyData1, AesMode::ECB, iv);

        REQUIRE(actualAes256EcbPlainText_KeyData.has_value());
        REQUIRE(actualAes256EcbPlainText_KeyData1.has_value());

        REQUIRE(actualAes256EcbPlainText_KeyData == TestVectors::plainText);
        REQUIRE(actualAes256EcbPlainText_KeyData1 == TestVectors::plainText);
    }

    SECTION("CBC Mode")
    {
        auto actualAes256CbcPlainText_KeyData = crypto.aes256Decrypt(key, TestVectors::expectedAes256CbcCipherText_KeyData, AesMode::CBC, iv);
        auto actualAes256CbcPlainText_KeyData1 = crypto.aes256Decrypt(key1, TestVectors::expectedAes256CbcCipherText_KeyData1, AesMode::CBC, iv);

        REQUIRE(actualAes256CbcPlainText_KeyData.has_value());
        REQUIRE(actualAes256CbcPlainText_KeyData1.has_value());

        REQUIRE(actualAes256CbcPlainText_KeyData == TestVectors::plainText);
        REQUIRE(actualAes256CbcPlainText_KeyData1 == TestVectors::plainText);
    }

    SECTION("CTR Mode")
    {
        auto actualAes256CtrPlainText_KeyData = crypto.aes256Decrypt(key, TestVectors::expectedAes256CtrCipherText_KeyData, AesMode::CTR, iv);
        auto actualAes256CtrPlainText_KeyData1 = crypto.aes256Decrypt(key1, TestVectors::expectedAes256CtrCipherText_KeyData1, AesMode::CTR, iv);

        REQUIRE(actualAes256CtrPlainText_KeyData.has_value());
        REQUIRE(actualAes256CtrPlainText_KeyData1.has_value());

        REQUIRE(actualAes256CtrPlainText_KeyData == TestVectors::plainText);
        REQUIRE(actualAes256CtrPlainText_KeyData1 == TestVectors::plainText);
    }
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::allZeroKeyData};
    auto iv = vector<uint8_t>(16, 0x00);

    auto plainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText_KeyData, AesMode::ECB, iv);

    REQUIRE_FALSE(plainText.has_value());
}

TEST_CASE("Decrypt cipher text with invalid cipher block mode of operation fails")
{
    Cryptography crypto;
    Key key{50, TestVectors::keyData};
    uint8_t invalidMode = 0xFF;
    auto iv = vector<uint8_t>(16, 0x00);

    auto plainText = crypto.aes256Decrypt(key, TestVectors::plainText, static_cast<AesMode>(invalidMode), iv);

    REQUIRE_FALSE(plainText.has_value());
}

TEST_CASE("Encrypt/decrypt success - AES256")
{
    Cryptography crypto;
    Key key{33, TestVectors::keyData};
    auto iv = vector<uint8_t>(16, 0x11);

    SECTION("ECB Mode")
    {
        auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::ECB, iv);

        REQUIRE(actualAes256EcbCipherText.has_value());
        REQUIRE(actualAes256EcbCipherText == TestVectors::expectedAes256EcbCipherText_KeyData);

        auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText_KeyData, AesMode::ECB, iv);

        REQUIRE(actualAes256EcbPlainText.has_value());
        REQUIRE(actualAes256EcbPlainText == TestVectors::plainText);
    }

    SECTION("CBC Mode")
    {
        auto actualAes256CbcCipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::CBC, iv);

        REQUIRE(actualAes256CbcCipherText.has_value());
        REQUIRE(actualAes256CbcCipherText == TestVectors::expectedAes256CbcCipherText_KeyData);

        auto actualAes256CbcPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256CbcCipherText_KeyData, AesMode::CBC, iv);

        REQUIRE(actualAes256CbcPlainText.has_value());
        REQUIRE(actualAes256CbcPlainText == TestVectors::plainText);
    }

    SECTION("CTR Mode")
    {
        auto actualAes256CtrCipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::CTR, iv);

        REQUIRE(actualAes256CtrCipherText.has_value());
        REQUIRE(actualAes256CtrCipherText == TestVectors::expectedAes256CtrCipherText_KeyData);

        auto actualAes256CtrPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256CtrCipherText_KeyData, AesMode::CTR, iv);

        REQUIRE(actualAes256CtrPlainText.has_value());
        REQUIRE(actualAes256CtrPlainText == TestVectors::plainText);
    }
}