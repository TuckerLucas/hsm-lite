#include "Keystore.hpp"

uint8_t Keystore::getNumKeys()
{
    return nKeys;
}

Key Keystore::getKey(Key key)
{
    return key;
}

bool Keystore::eraseKey(Key key)
{
    return false;
}

Key Keystore::updateKey(Key key)
{
    return key;
}

bool Keystore::injectKey(Key key)
{
    return key.id != 0;
}