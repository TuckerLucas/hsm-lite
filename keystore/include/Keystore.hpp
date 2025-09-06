#pragma once

#include "Key.hpp"
#include "KeystoreConstants.hpp"
#include "KeystoreStatus.hpp"

#include <cstdint>

class Keystore
{
public:
    uint16_t getNumKeys();

    KeystoreStatus getKey(Key key);

    KeystoreStatus eraseKey(Key key);

    KeystoreStatus updateKey(Key key);

    KeystoreStatus injectKey(Key key);

private: 
    bool keyIdIsDuplicated(uint16_t keyId);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::maxNumKeys]{}; 
};
