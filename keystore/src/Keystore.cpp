#include "Keystore.hpp"

#include <stdlib.h>
#include <algorithm>

uint16_t Keystore::getNumKeys()
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
    if(keyIsInjectable(key))
    {
        store[nKeys] = key;
        nKeys++;
        return true;
    }
    
    return false;
}

bool Keystore::keyIsInjectable(Key key)
{
    bool idIsValid = (key.id != 0);
    bool idIsUnique = !(*std::find(store, store+(KeystoreConstants::maxNumKeys-1), key)).hasValue();
    bool isSpaceAvailable = nKeys <= KeystoreConstants::maxNumKeys;

    return idIsValid && idIsUnique && isSpaceAvailable;
}