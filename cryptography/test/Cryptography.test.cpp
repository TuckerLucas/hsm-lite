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