#include "Keystore.hpp"

#include <stdlib.h>
#include <algorithm>

using namespace std;

uint16_t Keystore::getNumKeys()
{
    return nKeys;
}

vector<KeyId> Keystore::listKeyIds() const
{
    vector<KeyId> ids;
    
    for(size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if(store[i].id != 0)
        {
            ids.push_back(store[i].id);
        }
    }

    return ids;
}

optional<Key> Keystore::getKey(KeyId keyId)
{
    for(size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
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
    for(size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
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

KeystoreStatus Keystore::updateKey(KeyId keyId, KeyData updatedData)
{
    for(size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if(store[i].id == keyId)
        {
            if(store[i].data == updatedData)
            {
                return KeystoreStatus::DuplicateKeyData;
            }

            if(keyIsEmpty(updatedData))
            {
                return KeystoreStatus::KeyIsEmpty;
            }

            store[i].data = updatedData;

            return KeystoreStatus::Success;
        }
        else
        {
            continue;
        }
    }

    return KeystoreStatus::InvalidKeyId;
}

KeystoreStatus Keystore::injectKey(Key key)
{
    if(key.id == 0)
    {
        return KeystoreStatus::InvalidKeyId;
    }

    if(nKeys == KeystoreConstants::MaxNumKeys)
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
    
    for(size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if(store[i].id == 0)
        {
            store[i] = key;
            nKeys++;

            break;
        }
    }

    return KeystoreStatus::Success;
}

bool Keystore::keyIdIsDuplicated(KeyId keyId)
{
    for(size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
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
    for(size_t i = 0; i < KeystoreConstants::KeyDataSize; i++)
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