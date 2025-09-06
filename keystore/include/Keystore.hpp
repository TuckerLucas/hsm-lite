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

    bool eraseKey(Key key);

    Key updateKey(Key key);

    bool injectKey(Key key);

private: 
    bool keyIsInjectable(Key key);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::maxNumKeys]{}; 
};
