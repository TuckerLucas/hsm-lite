#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "Hash.hpp"
#include "Key.hpp"
#include "KeystoreConstants.hpp"
#include "StatusCode.hpp"

using namespace std;

class Keystore
{
public:
    uint16_t getNumKeys();

    vector<KeyId> listKeyIds() const;

    optional<Key> getKey(KeyId keyId);

    StatusCode eraseKey(KeyId keyId);

    StatusCode updateKey(KeyId keyId, const KeyData& updatedData);

    StatusCode injectKey(Key key);

private:
    bool keyIdIsDuplicated(KeyId keyId);

    uint16_t nKeys = 0;
    Key store[KeystoreConstants::MaxNumKeys]{};
};
