#include <catch2/catch_test_macros.hpp>

#include "Keystore.hpp"
#include "Key.hpp"

KeyData keyData = {0xAA, 0xBB, 0xCC};

TEST_CASE("New keystore has no keys") 
{
    Keystore keystore;

    REQUIRE(keystore.getNumKeys() == 0);
}

TEST_CASE("Get non-existent key")
{
    Keystore keystore;
    Key key{1};

    auto retrievedKey = keystore.getKey(key.id);

    REQUIRE(!(retrievedKey.has_value()));
}

TEST_CASE("Erase non-existent key")
{
    Keystore keystore;
    Key key{2};

    REQUIRE(keystore.eraseKey(key.id) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Update non-existent key")
{
    Keystore keystore;
    Key key{10};

    REQUIRE(keystore.updateKey(key.id, keyData) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Inject invalid key id")
{
    Keystore keystore;
    Key key;

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Inject empty key fails")
{
    Keystore keystore;
    Key key;

    key.id = 12U;

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::KeyIsEmpty);
}

TEST_CASE("Inject key successful")
{
    Keystore keystore;
    Key injectedKey{23, keyData};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKey.id);

    REQUIRE(retrievedKey.has_value());
    REQUIRE(retrievedKey.value() == injectedKey);
}

TEST_CASE("Number of keys increases after injection")
{
    Keystore keystore;
    Key key{};
    key.data = keyData;

    uint8_t nInjectedKeys = 23;

    for(size_t id = 1; id <= nInjectedKeys; id++)
    {
        key.id = id;
        REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    }

    REQUIRE(keystore.getNumKeys() == nInjectedKeys);
}

TEST_CASE("Inject duplicate key fails")
{
    Keystore keystore;
    Key key{150, keyData};

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    REQUIRE(keystore.injectKey(key) == KeystoreStatus::DuplicateKeyId);
}

TEST_CASE("Inject when keystore full fails")
{
    Keystore keystore;
    Key key;
    key.data = keyData;

    for(auto id = 1; id <= KeystoreConstants::MaxNumKeys; id++)
    {
        key.id = id;
        REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    }

    key.id = KeystoreConstants::MaxNumKeys+1;

    REQUIRE(keystore.getNumKeys() == KeystoreConstants::MaxNumKeys);
    REQUIRE(keystore.injectKey(key) == KeystoreStatus::KeystoreFull);
}

TEST_CASE("Get key after injection successful")
{
    Keystore keystore;
    KeyId injectedKeyId = 42U;
    Key injectedKey{injectedKeyId, keyData};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKeyId);

    REQUIRE(retrievedKey.has_value());
    REQUIRE(retrievedKey.value() == injectedKey);
}

TEST_CASE("Erase key after injection successful")
{
    Keystore keystore;
    Key injectedKey{10U, keyData};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    REQUIRE(keystore.eraseKey(injectedKey.id) == KeystoreStatus::Success);
    REQUIRE(!keystore.getKey(injectedKey.id).has_value());
}

TEST_CASE("Number of keys after erase decreases")
{
    Keystore keystore;
    Key key{};
    key.data = keyData;

    uint8_t nInjectedKeys = 44;
    uint8_t nErasedKeys = 11;

    for(size_t id = 1; id <= nInjectedKeys; id++)
    {
        key.id = id;
        REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    }

    REQUIRE(keystore.getNumKeys() == nInjectedKeys);

    for(size_t id = 1; id <= nErasedKeys; id++)
    {
        REQUIRE(keystore.eraseKey(id) == KeystoreStatus::Success);
    }

    REQUIRE(keystore.getNumKeys() == (nInjectedKeys - nErasedKeys));
}

TEST_CASE("Update key successful")
{
    Keystore keystore;
    Key injectedKey{39, keyData};

    KeyData updatedData = {0x01, 0x02, 0x03};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);
    REQUIRE(keystore.updateKey(injectedKey.id, updatedData) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKey.id);

    REQUIRE(retrievedKey.has_value());
    REQUIRE(retrievedKey->data == updatedData);
}

TEST_CASE("Update after erase fails")
{
    Keystore keystore;
    Key injectedKey{9, keyData};

    KeyData updatedData = {0x01, 0x02, 0x03};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);
    REQUIRE(keystore.eraseKey(injectedKey.id) == KeystoreStatus::Success);

    REQUIRE(keystore.updateKey(injectedKey.id, updatedData) == KeystoreStatus::InvalidKeyId);
}

TEST_CASE("Update key with same data fails")
{
    Keystore keystore;
    Key injectedKey{9, keyData};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    REQUIRE(keystore.updateKey(injectedKey.id, keyData) == KeystoreStatus::DuplicateKeyData);
}

TEST_CASE("Update key as empty fails")
{
    Keystore keystore;
    Key injectedKey{19, keyData};
    KeyData emptyKeyData{};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    REQUIRE(keystore.updateKey(injectedKey.id, emptyKeyData) == KeystoreStatus::KeyIsEmpty);
}