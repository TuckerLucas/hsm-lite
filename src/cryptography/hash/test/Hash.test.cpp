#include "Hash.hpp"

#include <stdlib.h>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "TestVectors.hpp"

using namespace std;

TEST_CASE("Hash key successful")
{
    Hash hasher;
    Key key{1, TestVectors::keyData32B};

    struct TestData
    {
        HashAlgorithm hashAlgo;
        vector<uint8_t> expectedHash;
    };

    auto testData =
        GENERATE(TestData{HashAlgorithm::SHA224, TestVectors::expectedSha224Hash_keyData32B},
                 TestData{HashAlgorithm::SHA256, TestVectors::expectedSha256Hash_keyData32B},
                 TestData{HashAlgorithm::SHA384, TestVectors::expectedSha384Hash_keyData32B},
                 TestData{HashAlgorithm::SHA512, TestVectors::expectedSha512Hash_keyData32B});

    auto actualHash = hasher.hashKey(key, testData.hashAlgo);

    REQUIRE(actualHash.has_value());

    REQUIRE(actualHash == testData.expectedHash);
}

TEST_CASE("Hash all zero key fails")
{
    Hash hasher;
    Key key{28, TestVectors::keyDataAllZeros};

    auto actualHashKeyData = hasher.hashKey(key, HashAlgorithm::SHA256);

    REQUIRE_FALSE(actualHashKeyData.has_value());
}

TEST_CASE("Hash key with invalid algorithm fails")
{
    Hash hasher;
    Key key{200, TestVectors::keyData32B};
    uint8_t invalidHashAlgorithm = 0xFF;

    auto actualHashKeyData = hasher.hashKey(key, static_cast<HashAlgorithm>(invalidHashAlgorithm));

    REQUIRE_FALSE(actualHashKeyData.has_value());
}