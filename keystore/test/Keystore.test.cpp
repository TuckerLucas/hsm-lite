#include <catch2/catch_test_macros.hpp>

#include "Keystore.hpp"
#include "Key.hpp"

TEST_CASE("New keystore has no keys") 
{
    Keystore keystore;

    REQUIRE(keystore.getNumKeys() == 0);
}

TEST_CASE("Get non-existent key")
{
    Keystore keystore;
    Key key;

    REQUIRE(!keystore.getKey(key).hasValue());
}
