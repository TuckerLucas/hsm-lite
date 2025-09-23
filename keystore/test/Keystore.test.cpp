#include <catch2/catch_test_macros.hpp>

#include "Keystore.hpp"
#include "Key.hpp"

#include <algorithm>

KeyData keyData = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 
                   0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 
                   0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20};

Hash256 expectedHashKeyData = {0xae, 0x21, 0x6c, 0x2e, 0xf5, 0x24, 0x7a, 0x37, 
                               0x82, 0xc1, 0x35, 0xef, 0xa2, 0x79, 0xa3, 0xe4, 
                               0xcd, 0xc6, 0x10, 0x94, 0x27, 0x0f, 0x5d, 0x2b,
                               0xe5, 0x8c, 0x62, 0x04, 0xb7, 0xa6, 0x12, 0xc9};

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

    REQUIRE_FALSE(retrievedKey.has_value());
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
    Cryptography crypto;
    Key injectedKey{23, keyData};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKey.id);
    REQUIRE(retrievedKey.has_value());

    auto actualHashKeyData = crypto.hashKeySha256(*retrievedKey);

    REQUIRE(actualHashKeyData.has_value());
    REQUIRE(actualHashKeyData == expectedHashKeyData);
}

TEST_CASE("Inject key successful, key ID boundary check")
{
    Keystore keystore;
    Cryptography crypto;
    Key injectedKey;

    injectedKey.id = std::numeric_limits<KeyId>::max();
    injectedKey.data = keyData;

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKey.id);
    REQUIRE(retrievedKey.has_value());

    auto actualHashKeyData = crypto.hashKeySha256(*retrievedKey);

    REQUIRE(actualHashKeyData.has_value());
    REQUIRE(actualHashKeyData == expectedHashKeyData);
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

    auto ids = keystore.listKeyIds();
    REQUIRE(std::find(ids.begin(), ids.end(), injectedKey.id) == ids.end());
}

TEST_CASE("Erase key when keystore full successful")
{
    Keystore keystore;
    Key injectedKey;

    injectedKey.data = keyData;

    for(size_t id = 1; id <= KeystoreConstants::MaxNumKeys; id++)
    {
        injectedKey.id = id;
        REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);
    }

    injectedKey.id = KeystoreConstants::MaxNumKeys + 1;
    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::KeystoreFull);

    REQUIRE(keystore.eraseKey(KeystoreConstants::MaxNumKeys) == KeystoreStatus::Success);
    
    auto ids = keystore.listKeyIds();
    REQUIRE(std::find(ids.begin(), ids.end(), injectedKey.id) == ids.end());
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
    Cryptography crypto;
    Key injectedKey{39, keyData};

    KeyData updatedData = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                           0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                           0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    Hash256 expectedHashUpdatedData = {0x47, 0x73, 0xd1, 0x2e, 0x23, 0x71, 0xbb, 0x93, 
                                       0x5b, 0x9a, 0x0f, 0x54, 0x39, 0xb4, 0xa1, 0xc3, 
                                       0xad, 0x3f, 0x24, 0x14, 0xb8, 0x69, 0x80, 0xf8, 
                                       0x41, 0x8d, 0x1c, 0xfa, 0xbd, 0xfa, 0xdf, 0xef};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);
    REQUIRE(keystore.updateKey(injectedKey.id, updatedData) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKey.id);
    REQUIRE(retrievedKey.has_value());

    auto actualHashUpdatedData = crypto.hashKeySha256(*retrievedKey);

    REQUIRE(actualHashUpdatedData.has_value());
    REQUIRE(expectedHashUpdatedData == actualHashUpdatedData);
}

TEST_CASE("Update key data succesively successful")
{
    Keystore keystore;
    Cryptography crypto;
    Key injectedKey{39, keyData};

    KeyData originalUpdatedData = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                   0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                                   0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
                                   0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    KeyData newUpdatedData = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                              0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                              0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
                              0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};

    Hash256 expectedHashOriginalUpdatedData = {0x47, 0x73, 0xd1, 0x2e, 0x23, 0x71, 0xbb, 0x93, 
                                               0x5b, 0x9a, 0x0f, 0x54, 0x39, 0xb4, 0xa1, 0xc3, 
                                               0xad, 0x3f, 0x24, 0x14, 0xb8, 0x69, 0x80, 0xf8, 
                                               0x41, 0x8d, 0x1c, 0xfa, 0xbd, 0xfa, 0xdf, 0xef};
                                               
    Hash256 expectedHashNewUpdatedData = {0x02, 0xd4, 0x49, 0xa3, 0x1f, 0xbb, 0x26, 0x7c, 
                                          0x8f, 0x35, 0x2e, 0x99, 0x68, 0xa7, 0x9e, 0x3e, 
                                          0x5f, 0xc9, 0x5c, 0x1b, 0xbe, 0xaa, 0x50, 0x2f, 
                                          0xd6, 0x45, 0x4e, 0xbd, 0xe5, 0xa4, 0xbe, 0xdc};

    REQUIRE(keystore.injectKey(injectedKey) == KeystoreStatus::Success);
    REQUIRE(keystore.updateKey(injectedKey.id, originalUpdatedData) == KeystoreStatus::Success);
    REQUIRE(keystore.updateKey(injectedKey.id, newUpdatedData) == KeystoreStatus::Success);

    auto retrievedKey = keystore.getKey(injectedKey.id);
    REQUIRE(retrievedKey.has_value());

    auto actualHashUpdatedData = crypto.hashKeySha256(*retrievedKey);
    REQUIRE(actualHashUpdatedData.has_value());

    REQUIRE_FALSE(actualHashUpdatedData == expectedHashOriginalUpdatedData);
    REQUIRE(actualHashUpdatedData == expectedHashNewUpdatedData);
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

TEST_CASE("New key is injected in first available slot")
{
    Keystore keystore;
    Key key;
    key.data = keyData;

    for(size_t id = 1; id <= 10; id++)
    {
        key.id = id;

        REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);
    }

    REQUIRE(keystore.eraseKey(5) == KeystoreStatus::Success);
    REQUIRE(keystore.eraseKey(7) == KeystoreStatus::Success);

    key.id = 11;

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);

    key.id = 12;

    REQUIRE(keystore.injectKey(key) == KeystoreStatus::Success);

    auto ids = keystore.listKeyIds();

    REQUIRE(ids == vector<KeyId>{1, 2, 3, 4, 11, 6, 12, 8, 9, 10});
}

TEST_CASE("Key equality")
{
    Keystore keystore;
    KeyData data1{0x01, 0x02, 0x44, 0xAB, 0x77}, 
            data2{0x01, 0x02, 0x44, 0xAB, 0x78};
    Key key1{12U, data1}, 
        key2{12U, data1}, 
        key3{12U, data2}, 
        key4{13U, data2};
    
    REQUIRE(key1 == key2);
    REQUIRE(key1 != key3);
    REQUIRE(key3 != key4);
}