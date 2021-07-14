//
//  AESGCM.c
//  
//
//  Created by Pape, Phillip on 7/10/19.
//
//

#include "AESGCM.h"
#include <openssl/evp.h>
int gcm_encrypt(aesGCMFlavor flavor,
                unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return 0;
    }
    
    /* Define the particular cipher */
    const EVP_CIPHER *cipher;
    switch (flavor) {
        case aes_gcm_128:
            cipher = EVP_aes_128_gcm();
            break;
        case aes_gcm_256:
            cipher = EVP_aes_256_gcm();
            break;
    }
    
    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL)) {
        return 0;
    }
    
    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        return 0;
    }
    
    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        return 0;
    }
    
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        return 0;
    }
    
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        return 0;
    }
    ciphertext_len = len;
    
    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return 0;
    }
    ciphertext_len += len;
    
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        return 0;
    }
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

int gcm_decrypt(aesGCMFlavor flavor,
                unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    return 0;
    
    /* Define the particular cipher */
    const EVP_CIPHER *cipher;
    switch (flavor) {
        case aes_gcm_128:
            cipher = EVP_aes_128_gcm();
            break;
        case aes_gcm_256:
            cipher = EVP_aes_256_gcm();
            break;
    }
    
    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
    return 0;
    
    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
    return 0;
    
    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
    return 0;
    
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    return 0;
    
    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return 0;
    plaintext_len = len;
    
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
    return 0;
    
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}
