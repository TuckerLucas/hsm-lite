#pragma once

#include "Key.hpp"

#include <cstdint>

class Keystore
{
public:
    uint8_t getNumKeys();

    Key getKey(Key key);

    bool eraseKey(Key key);

    Key updateKey(Key key);

    bool injectKey(Key key);

private: 
    uint8_t nKeys = 0;
};
