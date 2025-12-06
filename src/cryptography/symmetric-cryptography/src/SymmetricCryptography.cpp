#include "SymmetricCryptography.hpp"

optional<vector<uint8_t>> SymmetricCryptography::aesEncrypt(const Key& key,
                                                            const vector<uint8_t>& plainText,
                                                            AesKeySize aesKeySize,
                                                            CipherMode aesMode, optional<IV> iv)
{
    return aesCrypt(key, plainText, aesKeySize, aesMode, CipherOperation::Encrypt, iv);
}

optional<vector<uint8_t>> SymmetricCryptography::aesDecrypt(const Key& key,
                                                            const vector<uint8_t>& cipherText,
                                                            AesKeySize aesKeySize,
                                                            CipherMode aesMode, optional<IV> iv)
{
    return aesCrypt(key, cipherText, aesKeySize, aesMode, CipherOperation::Decrypt, iv);
}

optional<vector<uint8_t>> SymmetricCryptography::aesCrypt(const Key& key,
                                                          const vector<uint8_t>& input,
                                                          AesKeySize aesKeySize, CipherMode aesMode,
                                                          CipherOperation cipherOperation,
                                                          optional<IV> iv)
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
                case CipherMode::ECB:
                    cipher = EVP_aes_128_ecb();
                    break;
                case CipherMode::CBC:
                    cipher = EVP_aes_128_cbc();
                    break;
                case CipherMode::CTR:
                    cipher = EVP_aes_128_ctr();
                    break;
                default:
                    return nullopt;
            }

            break;

        case AesKeySize::AES192:

            switch (aesMode)
            {
                case CipherMode::ECB:
                    cipher = EVP_aes_192_ecb();
                    break;
                case CipherMode::CBC:
                    cipher = EVP_aes_192_cbc();
                    break;
                case CipherMode::CTR:
                    cipher = EVP_aes_192_ctr();
                    break;
                default:
                    return nullopt;
            }

            break;

        case AesKeySize::AES256:

            switch (aesMode)
            {
                case CipherMode::ECB:
                    cipher = EVP_aes_256_ecb();
                    break;
                case CipherMode::CBC:
                    cipher = EVP_aes_256_cbc();
                    break;
                case CipherMode::CTR:
                    cipher = EVP_aes_256_ctr();
                    break;
                default:
                    return nullopt;
            }

            break;

        default:
            return nullopt;
    }

    // RAII context management
    auto ctx = unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(EVP_CIPHER_CTX_new(),
                                                                          &EVP_CIPHER_CTX_free);

    if (!ctx)
    {
        return nullopt;
    }

    const unsigned char* ivPtr = nullptr;

    if (aesMode == CipherMode::ECB)
    {
        if (iv.has_value())
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

    vector<uint8_t> output(input.size() + EVP_CIPHER_block_size(cipher));
    int len = 0, totalLen = 0;

    int updateStatus =
        (cipherOperation == CipherOperation::Encrypt)
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
