#pragma once

#include "Cryptography.hpp"
#include "Key.hpp"
#include "KeystoreConstants.hpp"
#include "KeystoreStatus.hpp"

#include <cstdint>
#include <optional>
#include <vector>

using namespace std;

class Keystore
{
public:
    uint16_t getNumKeys();

    vector<KeyId> listKeyIds() const;

    optional<Key> getKey(KeyId keyId);

    KeystoreStatus eraseKey(KeyId keyId);

    KeystoreStatus updateKey(KeyId keyId, KeyData updatedData);

    KeystoreStatus injectKey(Key key);

private: 
    bool keyIdIsDuplicated(KeyId keyId);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::MaxNumKeys]{}; 
};
