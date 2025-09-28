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
    
    auto actualHashKeyData1 = crypto.hashKeySha256(key1);
    auto actualHashKeyData2 = crypto.hashKeySha256(key2);

    REQUIRE(actualHashKeyData1.has_value());
    REQUIRE(actualHashKeyData2.has_value());

    REQUIRE(actualHashKeyData1 == TestVectors::expectedHashKeyData1);
    REQUIRE(actualHashKeyData2 == TestVectors::expectedHashKeyData2);
}

TEST_CASE("Hash all zero key fails")
{
    Cryptography crypto;
    Key key{28, TestVectors::allZeroKeyData};

    auto actualHashKeyData = crypto.hashKeySha256(key);

    REQUIRE_FALSE(actualHashKeyData.has_value());
}

TEST_CASE("Encrypt plain text successful - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyData};

    auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText);

    REQUIRE(actualAes256EcbCipherText.has_value());
    REQUIRE(actualAes256EcbCipherText == TestVectors::expectedAes256EcbCipherText);
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    Cryptography crypto;
    Key key{7, TestVectors::allZeroKeyData};

    auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText);

    REQUIRE_FALSE(actualAes256EcbCipherText.has_value());
}

TEST_CASE("Decrypt cipher text successful - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyData};

    auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText);

    REQUIRE(actualAes256EcbPlainText.has_value());
    REQUIRE(actualAes256EcbPlainText == TestVectors::plainText);
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::allZeroKeyData};

    auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText);

    REQUIRE_FALSE(actualAes256EcbPlainText.has_value());
}

TEST_CASE("Encrypt/decrypt success - AES256")
{
    Cryptography crypto;
    Key key{33, TestVectors::keyData};

    auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText);

    REQUIRE(actualAes256EcbCipherText.has_value());
    REQUIRE(actualAes256EcbCipherText == TestVectors::expectedAes256EcbCipherText);

    auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText);

    REQUIRE(actualAes256EcbPlainText.has_value());
    REQUIRE(actualAes256EcbPlainText == TestVectors::plainText);
}