#ifndef SBS_USER_H
#define SBS_USER_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_USERNAME_LENGTH 64
#define PASSWORD_LENGTH 16
#define KEY_LENGTH 16

enum USER_ERROR {
    USER_OK = 0,
    USER_UNREGISTERED_ERROR,
    USER_ALREADY_REGISTERED_ERROR,
    USER_BAD_USERNAME_ERROR,
    USER_BAD_PASSWORD_ERROR,
    USER_DECRYPT_PASSWORD_ERROR,
    USER_PASSWORD_ENCRYPT_ERROR,
    USER_ALLOC_MEM_ERROR,
};

struct user {
    uint8_t name[MAX_USERNAME_LENGTH];
    uint8_t password[PASSWORD_LENGTH]; // the password must be encrypted
    uint8_t key[KEY_LENGTH]; // the key must be stored like md5 hash
};

int32_t acc_create_user (const uint8_t name[MAX_USERNAME_LENGTH], const uint8_t password[PASSWORD_LENGTH],
                         const uint8_t key[KEY_LENGTH]);
int32_t acc_user_get_info (uint8_t name[MAX_USERNAME_LENGTH], uint8_t password[PASSWORD_LENGTH],
                           uint8_t key[KEY_LENGTH]);
bool acc_user_is_registered ();
int32_t acc_decrypt_user_password (const uint8_t key[KEY_LENGTH], uint8_t password[PASSWORD_LENGTH]);
int32_t acc_free_user ();



#endif
