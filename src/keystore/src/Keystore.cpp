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

    for (size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if (store[i].id != 0)
        {
            ids.push_back(store[i].id);
        }
    }

    return ids;
}

optional<Key> Keystore::getKey(KeyId keyId)
{
    for (size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if (keyId == store[i].id)
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

StatusCode Keystore::eraseKey(KeyId keyId)
{
    for (size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if (keyId == store[i].id)
        {
            store[i] = {};
            nKeys--;

            return StatusCode::Success;
        }
        else
        {
            continue;
        }
    }

    return StatusCode::InvalidKeyId;
}

StatusCode Keystore::updateKey(KeyId keyId, const KeyData& updatedData)
{
    if (Key::isEmpty(updatedData))
    {
        return StatusCode::KeyDataIsEmpty;
    }

    for (auto& key : store)
    {
        if (key.id == keyId)
        {
            if (key.data == updatedData)
            {
                return StatusCode::DuplicateKeyData;
            }

            key.data = updatedData;

            return StatusCode::Success;
        }
    }

    return StatusCode::InvalidKeyId;
}

StatusCode Keystore::injectKey(Key key)
{
    if (key.id == 0)
    {
        return StatusCode::InvalidKeyId;
    }

    if (nKeys == KeystoreConstants::MaxNumKeys)
    {
        return StatusCode::KeystoreFull;
    }

    if (keyIdIsDuplicated(key.id))
    {
        return StatusCode::DuplicateKeyId;
    }

    if (key.isEmpty())
    {
        return StatusCode::KeyDataIsEmpty;
    }

    for (size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if (store[i].id == 0)
        {
            store[i] = key;
            nKeys++;

            break;
        }
    }

    return StatusCode::Success;
}

bool Keystore::keyIdIsDuplicated(KeyId keyId)
{
    for (size_t i = 0; i < KeystoreConstants::MaxNumKeys; i++)
    {
        if (keyId == store[i].id)
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