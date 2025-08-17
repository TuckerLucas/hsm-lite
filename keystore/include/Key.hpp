#pragma once

#include <cstdint>

class Key
{
public:
    bool hasValue()
    {
        return id != 0 ? true : false;
    }
private:
    uint8_t id = 0;
};