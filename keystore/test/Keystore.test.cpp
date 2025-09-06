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
    Key key{2};

    REQUIRE(keystore.eraseKey(key) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Update non-existent key")
{
    Keystore keystore;
    Key key{10};

    REQUIRE(keystore.updateKey(key) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Inject invalid key")
{
    Keystore keystore;
    Key key;

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Inject key successful")
{
    Keystore keystore;
    Key key{23};

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
}

TEST_CASE("Inject duplicate key fails")
{
    Keystore keystore;
    Key key{150};

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    REQUIRE(keystore.injectKey(key) == KeystoreStatus::DuplicateKeyId);
}

TEST_CASE("Inject when keystore full fails")
{
    Keystore keystore;
    Key key;

    for(uint16_t id = 1; id <= KeystoreConstants::maxNumKeys; id++)
    {
        key.id = id;
        REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    }

    key.id = KeystoreConstants::maxNumKeys+1;

    REQUIRE(keystore.getNumKeys() == KeystoreConstants::maxNumKeys);
    REQUIRE(keystore.injectKey(key) == KeystoreStatus::KeystoreFull);
}