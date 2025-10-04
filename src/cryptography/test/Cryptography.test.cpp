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

    auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::ECB);

    REQUIRE(actualAes256EcbCipherText.has_value());
    REQUIRE(actualAes256EcbCipherText == TestVectors::expectedAes256EcbCipherText);
}

TEST_CASE("Encrypt plain text with empty key fails")
{
    Cryptography crypto;
    Key key{7, TestVectors::allZeroKeyData};

    auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::ECB);

    REQUIRE_FALSE(actualAes256EcbCipherText.has_value());
}

TEST_CASE("Decrypt cipher text successful - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyData};

    auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText, AesMode::ECB);

    REQUIRE(actualAes256EcbPlainText.has_value());
    REQUIRE(actualAes256EcbPlainText == TestVectors::plainText);
}

TEST_CASE("Decrypt cipher text with empty key fails - AES256")
{
    Cryptography crypto;
    Key key{76, TestVectors::allZeroKeyData};

    auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText, AesMode::ECB);

    REQUIRE_FALSE(actualAes256EcbPlainText.has_value());
}

TEST_CASE("Encrypt/decrypt success - AES256")
{
    Cryptography crypto;
    Key key{33, TestVectors::keyData};

    auto actualAes256EcbCipherText = crypto.aes256Encrypt(key, TestVectors::plainText, AesMode::ECB);

    REQUIRE(actualAes256EcbCipherText.has_value());
    REQUIRE(actualAes256EcbCipherText == TestVectors::expectedAes256EcbCipherText);

    auto actualAes256EcbPlainText = crypto.aes256Decrypt(key, TestVectors::expectedAes256EcbCipherText, AesMode::ECB);

    REQUIRE(actualAes256EcbPlainText.has_value());
    REQUIRE(actualAes256EcbPlainText == TestVectors::plainText);
}