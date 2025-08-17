#pragma once

#include <cstdint>

class Key
{
public:
    bool operator==(const Key& rhs)
    {
        return this->id == rhs.id;
    }

    bool hasValue()
    {
        return id != 0;
    }

    uint8_t id = 0;
};