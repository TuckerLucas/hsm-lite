#include <openssl/sha.h>
#include "Cryptography.hpp"

Hash256 Cryptography::hashKeySha256(KeyData keyData)
{
    Hash256 hash{};
    SHA256_CTX ctx;
    
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, keyData.data(), keyData.size());
    SHA256_Final(hash.data(), &ctx);

    return hash;
}