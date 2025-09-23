#include <openssl/sha.h>
#include "Cryptography.hpp"

optional<Hash256> Cryptography::hashKeySha256(Key key)
{
    if(key.keyIsEmpty(key.data))
    {
        return nullopt;
    }

    Hash256 hash{};
    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, key.data.data(), key.data.size());
    SHA256_Final(hash.data(), &ctx);

    return hash;
}