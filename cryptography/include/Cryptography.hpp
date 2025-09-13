#pragma once

#include "Key.hpp"
#include "KeystoreStatus.hpp"

class Cryptography
{
public: 
    KeystoreStatus hashKey(KeyData keyData);
};