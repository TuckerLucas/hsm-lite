#include "Keystore.hpp"

#include <stdlib.h>
#include <algorithm>

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
    if(key.id != 0 && !(*std::find(store, store+255, key)).hasValue())
    {
        store[nKeys] = key;
        nKeys++;
        return true;
    }
    
    return false;
}