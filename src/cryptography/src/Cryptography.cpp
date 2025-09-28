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
        case HashAlgorithm::SHA256:
            
            hash.resize(32);
            SHA256_CTX sha256ctx;
            
            SHA256_Init(&sha256ctx);
            SHA256_Update(&sha256ctx, key.data.data(), key.data.size());
            SHA256_Final(hash.data(), &sha256ctx);

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

optional<vector<uint8_t>> Cryptography::aes256Encrypt(const Key& key, const vector<uint8_t>& plainText)
{
    if(key.isEmpty())
    {
        return nullopt;
    }

    // Ensure key size is correct (32 bytes for AES-256)
    if (key.data.size() != 32) 
    {
        return nullopt;
    }

    vector<uint8_t> cipherText{};
    cipherText.resize(32);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) 
    {
        return nullopt;
    }

    int len = 0;
    int cipherTextLen = 0;

    // Init AES-256-ECB encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data.data(), nullptr) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        return nullopt;
    }

    // Disable padding for deterministic output
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // Encrypt data
    if (EVP_EncryptUpdate(ctx, cipherText.data(), &len, plainText.data(), plainText.size()) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        return nullopt;
    }

    cipherTextLen = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, cipherText.data() + len, &len) != 1) 
    {
        EVP_CIPHER_CTX_free(ctx);
        return nullopt;
    }

    cipherTextLen += len;

    EVP_CIPHER_CTX_free(ctx);

    // Double-check we got exactly 32 bytes
    if (cipherTextLen != 32) 
    {
        return nullopt;
    }

    return cipherText;
}

std::optional<vector<uint8_t>> Cryptography::aes256Decrypt(const Key& key, const vector<uint8_t>& cipherText)
{
    if (Key::isEmpty(key.data))
    {
        return std::nullopt;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return std::nullopt;
    }

    vector<uint8_t> plainText{};
    plainText.resize(32);

    int outLen1 = 0;
    int outLen2 = 0;

    bool success = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data.data(), nullptr) != 1)
    {
        success = false;
    }

    // Disable padding (we want raw block)
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (success && EVP_DecryptUpdate(ctx,
                                     plainText.data(),
                                     &outLen1,
                                     cipherText.data(),
                                     static_cast<int>(cipherText.size())) != 1)
    {
        success = false;
    }

    if (success && EVP_DecryptFinal_ex(ctx, plainText.data() + outLen1, &outLen2) != 1)
    {
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!success)
    {
        return std::nullopt;
    }

    return plainText;
}