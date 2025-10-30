#pragma once

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <array>
#include <memory>
#include <optional>
#include <vector>

#include "CryptoCommon.hpp"
#include "Key.hpp"
#include "StatusCode.hpp"

class Hash
{
public:
    optional<vector<uint8_t>> hashKey(Key key, HashAlgorithm hashAlgorithm);
};