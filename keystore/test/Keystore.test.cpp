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
    Key key{1};

    REQUIRE(keystore.getKey(key) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Erase non-existent key")
{
    Keystore keystore;
    Key key;

    REQUIRE_FALSE(keystore.eraseKey(key));
}

TEST_CASE("Update non-existent key")
{
    Keystore keystore;
    Key key;

    REQUIRE_FALSE(keystore.updateKey(key).hasValue());
}

TEST_CASE("Inject invalid key")
{
    Keystore keystore;
    Key key;

    REQUIRE_FALSE(keystore.injectKey(key));
}

TEST_CASE("Inject key successful")
{
    Keystore keystore;
    Key key{23};

    REQUIRE(keystore.injectKey(key));
}

TEST_CASE("Inject duplicate key fails")
{
    Keystore keystore;
    Key key{150};

    REQUIRE(keystore.injectKey(key));
    REQUIRE_FALSE(keystore.injectKey(key));
}

TEST_CASE("Inject when keystore full fails")
{
    Keystore keystore;
    Key key;

    for(uint16_t id = 1; id <= KeystoreConstants::maxNumKeys; id++)
    {
        key.id = id;
        REQUIRE(keystore.injectKey(key));
    }

    key.id = KeystoreConstants::maxNumKeys+1;

    REQUIRE(keystore.getNumKeys() == KeystoreConstants::maxNumKeys);
    REQUIRE_FALSE(keystore.injectKey(key));
}