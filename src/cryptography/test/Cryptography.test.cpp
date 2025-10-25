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

TEST_CASE("Encrypt plain text successful")
{
    Cryptography crypto;
    Key key, key1;
    key.id = 76;
    key1.id = 36;

    SECTION("AES128")
    {
        key.data = TestVectors::keyData3;

        SECTION("ECB Mode")
        {
            auto actualAes128EcbCipherText_KeyData3 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128, AesMode::ECB, TestVectors::iv_all_ones);

            REQUIRE(actualAes128EcbCipherText_KeyData3.has_value());

            REQUIRE(actualAes128EcbCipherText_KeyData3 == TestVectors::expectedAes128EcbCipherText_KeyData3);
        }

        SECTION("CBC Mode")
        {
            auto actualAes128CbcCipherText_KeyData3 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128, AesMode::CBC, TestVectors::iv_all_ones);

            REQUIRE(actualAes128CbcCipherText_KeyData3.has_value());

            REQUIRE(actualAes128CbcCipherText_KeyData3 == TestVectors::expectedAes128CbcCipherText_KeyData3);
        }

        SECTION("CTR Mode")
        {
            auto actualAes128CtrCipherText_KeyData3 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128, AesMode::CTR, TestVectors::iv_all_ones);

            REQUIRE(actualAes128CtrCipherText_KeyData3.has_value());

            REQUIRE(actualAes128CtrCipherText_KeyData3 == TestVectors::expectedAes128CtrCipherText_KeyData3);
        }
    }

    SECTION("AES192")
    {
        key.data = TestVectors::keyData4;

        SECTION("ECB Mode")
        {
            auto actualAes192EcbCipherText_KeyData4 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES192, AesMode::ECB, TestVectors::iv_all_ones);

            REQUIRE(actualAes192EcbCipherText_KeyData4.has_value());

            REQUIRE(actualAes192EcbCipherText_KeyData4 == TestVectors::expectedAes192EcbCipherText_KeyData4);
        }

        SECTION("CBC Mode")
        {
            auto actualAes192CbcCipherText_KeyData4 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES192, AesMode::CBC, TestVectors::iv_all_ones);

            REQUIRE(actualAes192CbcCipherText_KeyData4.has_value());

            REQUIRE(actualAes192CbcCipherText_KeyData4 == TestVectors::expectedAes192CbcCipherText_KeyData4);
        }

        SECTION("CTR Mode")
        {
            auto actualAes192CtrCipherText_KeyData4 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES192, AesMode::CTR, TestVectors::iv_all_ones);

            REQUIRE(actualAes192CtrCipherText_KeyData4.has_value());

            REQUIRE(actualAes192CtrCipherText_KeyData4 == TestVectors::expectedAes192CtrCipherText_KeyData4);
        }
    }

    SECTION("AES256")
    {
        key.data = TestVectors::keyData;
        key1.data = TestVectors::keyData1;

        SECTION("ECB Mode")
        {
            auto actualAes256EcbCipherText_KeyData = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_ones);
            auto actualAes256EcbCipherText_KeyData1 = crypto.aesEncrypt(key1, TestVectors::plainText, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_ones);

            REQUIRE(actualAes256EcbCipherText_KeyData.has_value());
            REQUIRE(actualAes256EcbCipherText_KeyData1.has_value());

            REQUIRE(actualAes256EcbCipherText_KeyData == TestVectors::expectedAes256EcbCipherText_KeyData);
            REQUIRE(actualAes256EcbCipherText_KeyData1 == TestVectors::expectedAes256EcbCipherText_KeyData1);
        }

        SECTION("CBC Mode")
        {
            auto actualAes256CbcCipherText_KeyData = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::CBC, TestVectors::iv_all_ones);
            auto actualAes256CbcCipherText_KeyData1 = crypto.aesEncrypt(key1, TestVectors::plainText, AesKeySize::AES256, AesMode::CBC, TestVectors::iv_all_ones);
            
            REQUIRE(actualAes256CbcCipherText_KeyData.has_value());
            REQUIRE(actualAes256CbcCipherText_KeyData1.has_value());

            REQUIRE(actualAes256CbcCipherText_KeyData == TestVectors::expectedAes256CbcCipherText_KeyData);
            REQUIRE(actualAes256CbcCipherText_KeyData1 == TestVectors::expectedAes256CbcCipherText_KeyData1);        
        }

        SECTION("CTR Mode")
        {
            auto actualAes256CtrCipherText_KeyData = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::CTR, TestVectors::iv_all_ones);
            auto actualAes256CtrCipherText_KeyData1 = crypto.aesEncrypt(key1, TestVectors::plainText, AesKeySize::AES256, AesMode::CTR, TestVectors::iv_all_ones);

            REQUIRE(actualAes256CtrCipherText_KeyData.has_value());
            REQUIRE(actualAes256CtrCipherText_KeyData1.has_value()); 
            
            REQUIRE(actualAes256CtrCipherText_KeyData == TestVectors::expectedAes256CtrCipherText_KeyData);
            REQUIRE(actualAes256CtrCipherText_KeyData1 == TestVectors::expectedAes256CtrCipherText_KeyData1); 
        }
    }
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
    Key key{250, TestVectors::keyData};
    uint8_t invalidMode = 0xFF;

    auto cipherTextAes128 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES128, static_cast<AesMode>(invalidMode), TestVectors::iv_all_zeros);
    REQUIRE_FALSE(cipherTextAes128.has_value());

    key.data = TestVectors::keyData3;
    auto cipherTextAes192 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES192, static_cast<AesMode>(invalidMode), TestVectors::iv_all_zeros);
    REQUIRE_FALSE(cipherTextAes192.has_value());

    key.data = TestVectors::keyData4;
    auto cipherTextAes256 = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, static_cast<AesMode>(invalidMode), TestVectors::iv_all_zeros);
    REQUIRE_FALSE(cipherTextAes256.has_value());
}

TEST_CASE("Decrypt cipher text successful")
{
    Cryptography crypto;
    Key key{76, TestVectors::keyData};
    Key key1{88, TestVectors::keyData1};

    SECTION("AES128")
    {
        key.data = TestVectors::keyData3;

        SECTION("ECB Mode")
        {
            auto actualAes128EcbPlainText_KeyData3 = crypto.aesDecrypt(key, TestVectors::expectedAes128EcbCipherText_KeyData3, AesKeySize::AES128, AesMode::ECB, TestVectors::iv_all_ones);
        
            REQUIRE(actualAes128EcbPlainText_KeyData3.has_value());

            REQUIRE(actualAes128EcbPlainText_KeyData3 == TestVectors::plainText);
        }

        SECTION("CBC Mode")
        {
            auto actualAes128CbcPlainText_KeyData3 = crypto.aesDecrypt(key, TestVectors::expectedAes128CbcCipherText_KeyData3, AesKeySize::AES128, AesMode::CBC, TestVectors::iv_all_ones);
        
            REQUIRE(actualAes128CbcPlainText_KeyData3.has_value());

            REQUIRE(actualAes128CbcPlainText_KeyData3 == TestVectors::plainText);
        }

        SECTION("CTR Mode")
        {
            auto actualAes128CtrPlainText_KeyData3 = crypto.aesDecrypt(key, TestVectors::expectedAes128CtrCipherText_KeyData3, AesKeySize::AES128, AesMode::CTR, TestVectors::iv_all_ones);
        
            REQUIRE(actualAes128CtrPlainText_KeyData3.has_value());

            REQUIRE(actualAes128CtrPlainText_KeyData3 == TestVectors::plainText);
        }
    }

    SECTION("AES192")
    {
        key.data = TestVectors::keyData4;

        SECTION("ECB Mode")
        {
            auto actualAes192EcbPlainText_KeyData4 = crypto.aesDecrypt(key, TestVectors::expectedAes192EcbCipherText_KeyData4, AesKeySize::AES192, AesMode::ECB, TestVectors::iv_all_ones);
        
            REQUIRE(actualAes192EcbPlainText_KeyData4.has_value());

            REQUIRE(actualAes192EcbPlainText_KeyData4 == TestVectors::plainText);
        }

        SECTION("CBC Mode")
        {
            auto actualAes192CbcPlainText_KeyData4 = crypto.aesDecrypt(key, TestVectors::expectedAes192CbcCipherText_KeyData4, AesKeySize::AES192, AesMode::CBC, TestVectors::iv_all_ones);
        
            REQUIRE(actualAes192CbcPlainText_KeyData4.has_value());

            REQUIRE(actualAes192CbcPlainText_KeyData4 == TestVectors::plainText);
        }

        SECTION("CTR Mode")
        {
            auto actualAes192CtrPlainText_KeyData4 = crypto.aesDecrypt(key, TestVectors::expectedAes192CtrCipherText_KeyData4, AesKeySize::AES192, AesMode::CTR, TestVectors::iv_all_ones);
        
            REQUIRE(actualAes192CtrPlainText_KeyData4.has_value());

            REQUIRE(actualAes192CtrPlainText_KeyData4 == TestVectors::plainText);
        }
    }

    SECTION("AES256")
    {
        SECTION("ECB Mode")
        {
            auto actualAes256EcbPlainText_KeyData = crypto.aesDecrypt(key, TestVectors::expectedAes256EcbCipherText_KeyData, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_ones);
            auto actualAes256EcbPlainText_KeyData1 = crypto.aesDecrypt(key1, TestVectors::expectedAes256EcbCipherText_KeyData1, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_ones);

            REQUIRE(actualAes256EcbPlainText_KeyData.has_value());
            REQUIRE(actualAes256EcbPlainText_KeyData1.has_value());

            REQUIRE(actualAes256EcbPlainText_KeyData == TestVectors::plainText);
            REQUIRE(actualAes256EcbPlainText_KeyData1 == TestVectors::plainText);
        }

        SECTION("CBC Mode")
        {
            auto actualAes256CbcPlainText_KeyData = crypto.aesDecrypt(key, TestVectors::expectedAes256CbcCipherText_KeyData, AesKeySize::AES256, AesMode::CBC, TestVectors::iv_all_ones);
            auto actualAes256CbcPlainText_KeyData1 = crypto.aesDecrypt(key1, TestVectors::expectedAes256CbcCipherText_KeyData1, AesKeySize::AES256, AesMode::CBC, TestVectors::iv_all_ones);

            REQUIRE(actualAes256CbcPlainText_KeyData.has_value());
            REQUIRE(actualAes256CbcPlainText_KeyData1.has_value());

            REQUIRE(actualAes256CbcPlainText_KeyData == TestVectors::plainText);
            REQUIRE(actualAes256CbcPlainText_KeyData1 == TestVectors::plainText);
        }

        SECTION("CTR Mode")
        {
            auto actualAes256CtrPlainText_KeyData = crypto.aesDecrypt(key, TestVectors::expectedAes256CtrCipherText_KeyData, AesKeySize::AES256, AesMode::CTR, TestVectors::iv_all_ones);
            auto actualAes256CtrPlainText_KeyData1 = crypto.aesDecrypt(key1, TestVectors::expectedAes256CtrCipherText_KeyData1, AesKeySize::AES256, AesMode::CTR, TestVectors::iv_all_ones);

            REQUIRE(actualAes256CtrPlainText_KeyData.has_value());
            REQUIRE(actualAes256CtrPlainText_KeyData1.has_value());

            REQUIRE(actualAes256CtrPlainText_KeyData == TestVectors::plainText);
            REQUIRE(actualAes256CtrPlainText_KeyData1 == TestVectors::plainText);
        }
    }
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

TEST_CASE("Encrypt/decrypt success - AES256")
{
    Cryptography crypto;
    Key key{33, TestVectors::keyData};

    SECTION("ECB Mode")
    {
        auto actualAes256EcbCipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_ones);

        REQUIRE(actualAes256EcbCipherText.has_value());
        REQUIRE(actualAes256EcbCipherText == TestVectors::expectedAes256EcbCipherText_KeyData);

        auto actualAes256EcbPlainText = crypto.aesDecrypt(key, TestVectors::expectedAes256EcbCipherText_KeyData, AesKeySize::AES256, AesMode::ECB, TestVectors::iv_all_ones);

        REQUIRE(actualAes256EcbPlainText.has_value());
        REQUIRE(actualAes256EcbPlainText == TestVectors::plainText);
    }

    SECTION("CBC Mode")
    {
        auto actualAes256CbcCipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::CBC, TestVectors::iv_all_ones);

        REQUIRE(actualAes256CbcCipherText.has_value());
        REQUIRE(actualAes256CbcCipherText == TestVectors::expectedAes256CbcCipherText_KeyData);

        auto actualAes256CbcPlainText = crypto.aesDecrypt(key, TestVectors::expectedAes256CbcCipherText_KeyData, AesKeySize::AES256, AesMode::CBC, TestVectors::iv_all_ones);

        REQUIRE(actualAes256CbcPlainText.has_value());
        REQUIRE(actualAes256CbcPlainText == TestVectors::plainText);
    }

    SECTION("CTR Mode")
    {
        auto actualAes256CtrCipherText = crypto.aesEncrypt(key, TestVectors::plainText, AesKeySize::AES256, AesMode::CTR, TestVectors::iv_all_ones);

        REQUIRE(actualAes256CtrCipherText.has_value());
        REQUIRE(actualAes256CtrCipherText == TestVectors::expectedAes256CtrCipherText_KeyData);

        auto actualAes256CtrPlainText = crypto.aesDecrypt(key, TestVectors::expectedAes256CtrCipherText_KeyData, AesKeySize::AES256, AesMode::CTR, TestVectors::iv_all_ones);

        REQUIRE(actualAes256CtrPlainText.has_value());
        REQUIRE(actualAes256CtrPlainText == TestVectors::plainText);
    }
}