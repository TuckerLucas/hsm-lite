#pragma once

#include "Key.hpp"
#include "KeystoreConstants.hpp"

#include <cstdint>

class Keystore
{
public:
    uint16_t getNumKeys();

    Key getKey(Key key);

    bool eraseKey(Key key);

    Key updateKey(Key key);

    bool injectKey(Key key);

private: 
    bool keyIsInjectable(Key key);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::maxNumKeys]{}; 
};
