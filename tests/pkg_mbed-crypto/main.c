
#include <stdio.h>
#include <string.h>

#include "psa/crypto.h"
#include "mbedtls/version.h"

#define SOME_PLAINTEXT "I am plaintext."

#define SOME_CIPHERTEXT \
{ \
0x9f, 0xbf, 0x0b, 0x99, 0x70, 0xe0, 0x3d, 0xab, \
0xf7, 0x65, 0x43, 0x88, 0x09, 0x2c, 0xb4, 0x66, \
}

#define ENCRYPTED_WITH_IV \
{ \
0x0e, 0x42, 0x75, 0x78, 0xb5, 0x0d, 0x17, 0x4f, \
0x6e, 0x13, 0xf4, 0xfd, 0x16, 0x30, 0x3e, 0xc7, \
}

static const uint8_t AES_KEY[] =
{
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};

static void import_a_key(const uint8_t *key, size_t key_len)
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t handle;

    printf("Import an AES key...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Set key attributes */
    psa_set_key_usage_flags(&attributes, 0);
    psa_set_key_algorithm(&attributes, 0);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);

    /* Import the key */
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import key\n");
        return;
    }
    printf("Imported a key\n");

    /* Free the attributes */
    psa_reset_key_attributes(&attributes);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void encrypt_with_symmetric_ciphers(const uint8_t *key, size_t key_len)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    uint8_t plaintext[block_size] = SOME_PLAINTEXT;
    uint8_t iv[block_size];
    size_t iv_len;
    uint8_t output[block_size];
    size_t output_len;
    psa_key_handle_t handle;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

    printf("Encrypt with cipher...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Encrypt the plaintext */
    status = psa_cipher_encrypt_setup(&operation, handle, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }
    status = psa_cipher_generate_iv(&operation, iv, sizeof(iv), &iv_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to generate IV\n");
        return;
    }
    status = psa_cipher_update(&operation, plaintext, sizeof(plaintext),
                               output, sizeof(output), &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to update cipher operation\n");
        return;
    }
    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    printf("Encrypted plaintext\n");

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

static void decrypt_with_symmetric_ciphers(const uint8_t *key, size_t key_len)
{
    enum {
        block_size = PSA_BLOCK_CIPHER_BLOCK_SIZE(PSA_KEY_TYPE_AES),
    };
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
    psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;
    uint8_t ciphertext[block_size] = SOME_CIPHERTEXT;
    uint8_t iv[block_size] = ENCRYPTED_WITH_IV;
    uint8_t output[block_size];
    size_t output_len;
    psa_key_handle_t handle;

    printf("Decrypt with cipher...\t");
    fflush(stdout);

    /* Initialize PSA Crypto */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        printf("Failed to initialize PSA Crypto\n");
        return;
    }

    /* Import a key */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 128);
    status = psa_import_key(&attributes, key, key_len, &handle);
    if (status != PSA_SUCCESS) {
        printf("Failed to import a key\n");
        return;
    }
    psa_reset_key_attributes(&attributes);

    /* Decrypt the ciphertext */
    status = psa_cipher_decrypt_setup(&operation, handle, alg);
    if (status != PSA_SUCCESS) {
        printf("Failed to begin cipher operation\n");
        return;
    }
    status = psa_cipher_set_iv(&operation, iv, sizeof(iv));
    if (status != PSA_SUCCESS) {
        printf("Failed to set IV\n");
        return;
    }
    status = psa_cipher_update(&operation, ciphertext, sizeof(ciphertext),
                               output, sizeof(output), &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to update cipher operation\n");
        return;
    }
    status = psa_cipher_finish(&operation, output + output_len,
                               sizeof(output) - output_len, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Failed to finish cipher operation\n");
        return;
    }
    printf("Decrypted ciphertext\n");

    /* Clean up cipher operation context */
    psa_cipher_abort(&operation);

    /* Destroy the key */
    psa_destroy_key(handle);

    mbedtls_psa_crypto_free();
}

int main(void)
{
    puts("mbed-crypto test\n");

    import_a_key(AES_KEY, sizeof(AES_KEY));
    encrypt_with_symmetric_ciphers(AES_KEY, sizeof(AES_KEY));
    decrypt_with_symmetric_ciphers(AES_KEY, sizeof(AES_KEY));

    printf("Finished\n");

    return 0;
}