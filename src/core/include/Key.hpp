#pragma once

#include <cstdint>
#include <vector>

#include "KeystoreConstants.hpp"

using namespace std;

using KeyId = uint16_t;
using KeyData = vector<uint8_t>;

class Key
{
public:
    bool operator==(const Key& rhs) const
    {
        return (this->id == rhs.id && this->data == rhs.data);
    }

    bool operator!=(const Key& rhs) const
    {
        return !(this->id == rhs.id && this->data == rhs.data);
    }

    bool isEmpty() const
    {
        return isEmpty(this->data);
    }

    static bool isEmpty(const KeyData& data)
    {
        for (auto byte : data)
        {
            if (byte != 0)
            {
                return false;
            }
        }

        return true;
    }

    bool isNotEmpty()
    {
        return !isEmpty();
    }

    KeyId id = 0U;
    KeyData data{};
};