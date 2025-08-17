#include "Keystore.hpp"

uint8_t Keystore::getNumKeys()
{
    return nKeys;
}

Key Keystore::getKey(Key key)
{
    return key;
}