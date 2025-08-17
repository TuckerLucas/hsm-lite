#pragma once

#include "Key.hpp"

#include <cstdint>

class Keystore
{
public:
    uint8_t getNumKeys();

    Key getKey(Key key);

private: 
    uint8_t nKeys = 0;
};
