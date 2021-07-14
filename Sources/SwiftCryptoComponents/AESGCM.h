//
//  AESGCM.h
//  
//
//  Created by Pape, Phillip on 7/10/19.
//  
//

#ifndef AESGCM_h
#define AESGCM_h

#include <stdio.h>

//#include <openssl/evp.h>

// Code adapted from the example found here:
// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
// Note that we also are removing padding using EVP_CIPHER_CTX_set_padding(ctx, 0);
// This has to be used after all evp elements are initialized

typedef enum {
    aes_gcm_128 = 0,
    aes_gcm_256 = 1
} aesGCMFlavor;

int gcm_encrypt(aesGCMFlavor flavor,
                unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);

int gcm_decrypt(aesGCMFlavor flavor,
                unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

#endif /* AESGCM_h */
