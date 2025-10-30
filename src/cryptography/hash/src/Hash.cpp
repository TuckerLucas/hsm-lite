#include "Hash.hpp"

optional<vector<uint8_t>> Hash::hashKey(Key key, HashAlgorithm hashAlgorithm)
{
    if (key.isEmpty())
    {
        return nullopt;
    }

    vector<uint8_t> hash{};

    switch (hashAlgorithm)
    {
        case HashAlgorithm::SHA224:

            hash.resize(28);

            // Open SSL uses the same context type for SHA224 and SHA256
            SHA256_CTX sha224ctx;

            SHA224_Init(&sha224ctx);
            SHA224_Update(&sha224ctx, key.data.data(), key.data.size());
            SHA224_Final(hash.data(), &sha224ctx);

            break;

        case HashAlgorithm::SHA256:

            hash.resize(32);
            SHA256_CTX sha256ctx;

            SHA256_Init(&sha256ctx);
            SHA256_Update(&sha256ctx, key.data.data(), key.data.size());
            SHA256_Final(hash.data(), &sha256ctx);

            break;

        case HashAlgorithm::SHA384:

            hash.resize(48);

            // Open SSL uses the same context type for SHA384 and SHA512
            SHA512_CTX sha384ctx;

            SHA384_Init(&sha384ctx);
            SHA384_Update(&sha384ctx, key.data.data(), key.data.size());
            SHA384_Final(hash.data(), &sha384ctx);
            break;

        case HashAlgorithm::SHA512:

            hash.resize(64);
            SHA512_CTX sha512ctx;

            SHA512_Init(&sha512ctx);
            SHA512_Update(&sha512ctx, key.data.data(), key.data.size());
            SHA512_Final(hash.data(), &sha512ctx);

            break;

        default:

            return nullopt;
    }

    return hash;
}
