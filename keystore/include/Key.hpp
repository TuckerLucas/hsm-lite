#pragma once

#include <cstdint>

class Key
{
public:
    bool operator==(const Key& rhs) const
    {
        return this->id == rhs.id;
    }

    uint16_t id = 0;
};