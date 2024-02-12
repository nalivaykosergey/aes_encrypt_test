#ifndef AES_CRYPT_H
#define AES_CRYPT_H

#include <stdint.h>

enum AES_CRYPT_ERRORS {
    AES_CRYPT_OK = 0,
    AES_CRYPT_UNDEFINED_ERROR,
    AES_CRYPT_BAD_USER_INPUT_ERROR,
    AES_CRYPT_PACK_ERROR
};

int aes_encrypt (const uint8_t * text, const uint8_t * key, uint8_t * cypher_text);
int aes_decrypt (const uint8_t * cypher_text, const uint8_t * key, uint8_t * text);

#endif
