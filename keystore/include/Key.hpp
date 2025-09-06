#pragma once

#include <cstdint>

using KeyId = uint16_t;

class Key
{
public:
    bool operator==(const Key& rhs) const
    {
        return this->id == rhs.id;
    }

    KeyId id = 0;
};