#include "Keystore.hpp"

#include <stdlib.h>
#include <algorithm>

uint16_t Keystore::getNumKeys()
{
    return nKeys;
}

KeystoreStatus Keystore::getKey(Key key)
{
    return KeystoreStatus::InvalidKeyId;
}

KeystoreStatus Keystore::eraseKey(Key key)
{
    return KeystoreStatus::InvalidKeyId;
}

KeystoreStatus Keystore::updateKey(Key key)
{
    return KeystoreStatus::InvalidKeyId;
}

KeystoreStatus Keystore::injectKey(Key key)
{
    if(key.id == 0)
    {
        return KeystoreStatus::InvalidKeyId;
    }

    if(nKeys == KeystoreConstants::maxNumKeys)
    {
        return KeystoreStatus::KeystoreFull;
    }
        
    if(keyIdIsDuplicated(key))
    {
        return KeystoreStatus::DuplicateKeyId;
    }
    
    store[nKeys] = key;
    nKeys++;
    return KeystoreStatus::Success;
}

bool Keystore::keyIdIsDuplicated(Key key)
{
    return (*std::find(store, store+(KeystoreConstants::maxNumKeys-1), key)).hasValue();
}