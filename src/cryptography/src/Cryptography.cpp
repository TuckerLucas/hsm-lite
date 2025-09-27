#include "Cryptography.hpp"

optional<Hash256> Cryptography::hashKeySha256(Key key)
{
    if(key.isEmpty())
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

optional<array<std::uint8_t, 32U>> Cryptography::aes256Encrypt(Key key, std::array<uint8_t, 32> plainText)
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

    array<uint8_t, 32> cipherText{};

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

std::optional<std::array<std::uint8_t, 32U>> Cryptography::aes256Decrypt(const Key& key, const std::array<std::uint8_t, 32U>& cipherText)
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

    std::array<std::uint8_t, 32U> plainText{};
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