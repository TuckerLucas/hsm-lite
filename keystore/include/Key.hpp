#pragma once

#include <cstdint>
#include <array>

using namespace std;

using KeyId = uint16_t;
using KeyData = array<uint8_t, 32>;

class Key
{
public:
    bool operator==(const Key& rhs) const
    {
        return this->id == rhs.id;
    }

    KeyId id = 0;
    KeyData data;
};