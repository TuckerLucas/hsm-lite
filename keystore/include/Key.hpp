#pragma once

#include <cstdint>

class Key
{
public:
    bool hasValue()
    {
        return id != 0;
    }

    uint8_t id = 0;
};