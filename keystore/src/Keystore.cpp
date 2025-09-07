#include "Keystore.hpp"

#include <stdlib.h>
#include <algorithm>

using namespace std;

uint16_t Keystore::getNumKeys()
{
    return nKeys;
}

optional<Key> Keystore::getKey(KeyId keyId)
{
    for(auto i = 0; i < KeystoreConstants::maxNumKeys; i++)
    {
        if(keyId == store[i].id)
        {
            return store[i];
        }
        else
        {
            continue;
        }
    }

    return nullopt;
}

KeystoreStatus Keystore::eraseKey(KeyId keyId)
{
    for(auto i = 0; i < KeystoreConstants::maxNumKeys; i++)
    {
        if(keyId == store[i].id)
        {
            store[i] = {};
            nKeys--;

            return KeystoreStatus::Success;
        }
        else
        {
            continue;
        }
    }

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

    if(keyIdIsDuplicated(key.id))
    {
        return KeystoreStatus::DuplicateKeyId;
    }

    if(keyIsEmpty(key.data))
    {
        return KeystoreStatus::KeyIsEmpty;
    }
    
    store[nKeys] = key;
    nKeys++;
    return KeystoreStatus::Success;
}

bool Keystore::keyIdIsDuplicated(KeyId keyId)
{
    for(auto i = 0; i < KeystoreConstants::maxNumKeys; i++)
    {
        if(keyId == store[i].id)
        {
            return true;
        }
        else
        {
            continue;
        }
    }

    return false;
}

bool Keystore::keyIsEmpty(KeyData keyData)
{
    for(auto i = 0; i < 32; i++)
    {
        if(keyData[i] != 0)
        {
            return false;
        }
        else
        {
            continue;
        }
    }

    return true;
}