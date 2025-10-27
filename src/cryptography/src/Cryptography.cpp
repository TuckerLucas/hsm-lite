#include "Cryptography.hpp"

optional<vector<uint8_t>> Cryptography::hashKey(Key key, HashAlgorithm hashAlgorithm)
{
    if(key.isEmpty())
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

optional<vector<uint8_t>> Cryptography::aesEncrypt(const Key& key, const vector<uint8_t>& plainText, AesKeySize aesKeySize, AesMode aesMode, PaddingMode paddingMode, optional<IV> iv)
{
    return aesCrypt(key, plainText, aesKeySize, aesMode, paddingMode, CipherOperation::Encrypt, iv);
}

optional<vector<uint8_t>> Cryptography::aesDecrypt(const Key& key, const vector<uint8_t>& cipherText, AesKeySize aesKeySize, AesMode aesMode, PaddingMode paddingMode, optional<IV> iv)
{
    return aesCrypt(key, cipherText, aesKeySize, aesMode, paddingMode, CipherOperation::Decrypt, iv);
}

optional<vector<uint8_t>> Cryptography::aesCrypt(const Key& key, const vector<uint8_t>& input, AesKeySize aesKeySize, AesMode aesMode, PaddingMode paddingMode, CipherOperation cipherOperation, optional<IV> iv)
{
    if (key.isEmpty())
    {
        return nullopt;
    }
   
    const EVP_CIPHER* cipher = nullptr;

    switch (aesKeySize)
    {
        case AesKeySize::AES128: 
        
            switch (aesMode)
            {
                case AesMode::ECB: cipher = EVP_aes_128_ecb(); break;
                case AesMode::CBC: cipher = EVP_aes_128_cbc(); break;
                case AesMode::CTR: cipher = EVP_aes_128_ctr(); break;
                default: return nullopt;
            }
        
            break;

        case AesKeySize::AES192: 
        
            switch (aesMode)
            {
                case AesMode::ECB: cipher = EVP_aes_192_ecb(); break;
                case AesMode::CBC: cipher = EVP_aes_192_cbc(); break;
                case AesMode::CTR: cipher = EVP_aes_192_ctr(); break;
                default: return nullopt;
            }
        
            break;

        case AesKeySize::AES256:

            switch (aesMode)
            {
                case AesMode::ECB: cipher = EVP_aes_256_ecb(); break;
                case AesMode::CBC: cipher = EVP_aes_256_cbc(); break;
                case AesMode::CTR: cipher = EVP_aes_256_ctr(); break;
                default: return nullopt;
            }

            break;

        default: return nullopt;
    }

    // RAII context management
    auto ctx = unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);

    if (!ctx)
    {
        return nullopt;
    }

    const unsigned char* ivPtr = nullptr;

    if(aesMode == AesMode::ECB)
    {
        if(iv.has_value())
        {
            return nullopt;
        }
    }
    else
    {
        if (!iv.has_value())
        {
            return nullopt;
        }
        
        if (iv->size() != static_cast<size_t>(EVP_CIPHER_iv_length(cipher)))
        {
            return nullopt;
        }

        ivPtr = iv->data();
    }

    int initStatus = (cipherOperation == CipherOperation::Encrypt)
        ? EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, key.data.data(), ivPtr)
        : EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, key.data.data(), ivPtr);

    if (initStatus != 1)
    {
        return nullopt;
    }

    if(paddingMode == PaddingMode::None)
    {
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0);
    }

    vector<uint8_t> output(input.size() + EVP_CIPHER_block_size(cipher));
    int len = 0, totalLen = 0;

    int updateStatus = (cipherOperation == CipherOperation::Encrypt)
        ? EVP_EncryptUpdate(ctx.get(), output.data(), &len, input.data(), input.size())
        : EVP_DecryptUpdate(ctx.get(), output.data(), &len, input.data(), input.size());

    if (updateStatus != 1)
    {
        return nullopt;
    }

    totalLen = len;

    int finalStatus = (cipherOperation == CipherOperation::Encrypt)
        ? EVP_EncryptFinal_ex(ctx.get(), output.data() + len, &len)
        : EVP_DecryptFinal_ex(ctx.get(), output.data() + len, &len);

    if (finalStatus != 1)
    {
        return nullopt;
    }

    totalLen += len;
    output.resize(totalLen);

    return output;
}

