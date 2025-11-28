#include "AsymmetricCryptography.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

optional<KeyPair> AsymmetricCryptography::rsaGenerateKeyPair()
{
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx)
    {
        return nullopt;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0)
    {
        return nullopt;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
    {
        return nullopt;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    {
        return nullopt;
    }

    KeyPair pair;

    BIO* privBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privBio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    // Get bytes from the BIO into your vector
    BUF_MEM* privBuf;
    BIO_get_mem_ptr(privBio, &privBuf);

    pair.privateKey.data.assign(privBuf->data, privBuf->data + privBuf->length);

    BIO_free(privBio);

    // Extract the RSA struct from EVP_PKEY
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    // Create a new EVP_PKEY for the public key
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, RSAPublicKey_dup(rsa));  // duplicate only public part

    // Write public key to PEM
    BIO* pubBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubBio, pubKey);

    BUF_MEM* pubBuf;
    BIO_get_mem_ptr(pubBio, &pubBuf);

    pair.publicKey.data.assign(pubBuf->data, pubBuf->data + pubBuf->length);

    // Cleanup
    RSA_free(rsa);
    BIO_free(pubBio);
    EVP_PKEY_free(pubKey);

    EVP_PKEY_CTX_free(ctx);
    return pair;
}