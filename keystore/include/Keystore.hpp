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

    KeystoreStatus eraseKey(Key key);

    KeystoreStatus updateKey(Key key);

    KeystoreStatus injectKey(Key key);

private: 
    bool keyIdIsDuplicated(KeyId keyId);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::maxNumKeys]{}; 
};
