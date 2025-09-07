#pragma once

#include "Key.hpp"
#include "KeystoreConstants.hpp"
#include "KeystoreStatus.hpp"

#include <cstdint>
#include <optional>

using namespace std;

class Keystore
{
public:
    uint16_t getNumKeys();

    optional<Key> getKey(KeyId keyId);

    KeystoreStatus eraseKey(KeyId keyId);

    KeystoreStatus updateKey(KeyId keyId, KeyData updatedData);

    KeystoreStatus injectKey(Key key);

private: 
    bool keyIdIsDuplicated(KeyId keyId);
    bool keyIsEmpty(KeyData keyData);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::MaxNumKeys]{}; 
};
