#include "user.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include <mbedtls/md5.h>
#include <aes_crypt.h>


struct user * global_user = NULL;

static bool acc_is_valid_name (const uint8_t * name)
{
    size_t username_length;

    if (name == NULL) {
        return false;
    }

    username_length = strnlen(name, MAX_USERNAME_LENGTH);

    if (username_length < 5) {
        return false;
    }

    for (size_t i = 0; i < username_length; ++i) {
        if (!isalpha(name[i]) && !isdigit(name[i]))
            return false;
    }

    return true;
}


static bool acc_is_valid_password (const uint8_t * password)
{
    size_t username_length;

    if (password == NULL) {
        return false;
    }

    username_length = strnlen(password, PASSWORD_LENGTH);

    if (username_length < 5) {
        return false;
    }

    for (size_t i = 0; i < username_length; ++i) {
        if (!isalpha(password[i]) && !isdigit(password[i]))
            return false;
    }

    return true;
}


int32_t acc_create_user (const uint8_t name[MAX_USERNAME_LENGTH], const uint8_t password[PASSWORD_LENGTH],
                         const uint8_t key[KEY_LENGTH])
{
    int rv;
    mbedtls_md5_context ctx;

    if (global_user != NULL) {
        return USER_ALREADY_REGISTERED_ERROR;
    }

    if (!acc_is_valid_name(name)) {
        fprintf(stdout, "Invalid username\n");
        return USER_BAD_USERNAME_ERROR;
    }
    if (!acc_is_valid_password(password)) {
        fprintf(stdout, "Invalid password\n");
        return USER_BAD_PASSWORD_ERROR;
    }

    global_user = malloc(sizeof(struct user));

    if (global_user == NULL) {
        fprintf(stdout, "Unable to allocate data\n");
        return USER_ALLOC_MEM_ERROR;
    }

    memcpy(global_user->name, name, strlen(name));

    mbedtls_md5_init(&ctx);
    mbedtls_md5_starts(&ctx);
    mbedtls_md5_update(&ctx, key, KEY_LENGTH);
    mbedtls_md5_finish(&ctx, global_user->key);
    mbedtls_md5_free(&ctx);

    rv = aes_encrypt(password, key, global_user->password);

    if (rv != AES_CRYPT_OK) {
        fprintf(stderr, "Unable to encrypt data using entered values\n");
        acc_free_user();
        return USER_PASSWORD_ENCRYPT_ERROR;
    }

    return USER_OK;
}


int32_t acc_user_get_info (uint8_t name[MAX_USERNAME_LENGTH], uint8_t password[PASSWORD_LENGTH],
                           uint8_t key[KEY_LENGTH])
{
    if (global_user == NULL) {
        return USER_UNREGISTERED_ERROR;
    }

    memcpy(name, global_user->name, MAX_USERNAME_LENGTH);
    memcpy(password, global_user->password, PASSWORD_LENGTH);
    memcpy(key, global_user->key, KEY_LENGTH);

    return USER_OK;
}


bool acc_user_is_registered ()
{
    return global_user != NULL;
}


int32_t acc_decrypt_user_password (const uint8_t key[KEY_LENGTH], uint8_t password[PASSWORD_LENGTH])
{
    int rv;
    if (global_user == NULL) {
        return USER_UNREGISTERED_ERROR;
    }

    rv = aes_decrypt(global_user->password, key, password);

    if (rv != AES_CRYPT_OK) {
        return USER_DECRYPT_PASSWORD_ERROR;
    }

    return USER_OK;
}


int32_t acc_free_user ()
{
    if (global_user == NULL) {
        return USER_UNREGISTERED_ERROR;
    }
    free(global_user);
    global_user = NULL;
    return USER_OK;
}