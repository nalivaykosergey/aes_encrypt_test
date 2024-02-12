#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <readline/readline.h>

#include "accounting/user.h"

static bool PROGRAM_MUST_EXIT;

typedef enum COMMAND_TYPE_ {
    UNDEFINED_CMD = 0,
    HELP_CMD,
    REGISTER_CMD,
    PRINT_USER_INFO_CMD,
    DECRYPT_PASSWORD_CMD,
    EXIT_CMD,
} COMMAND_TYPE_T;


static void help_cmd_process()
{
    printf("Help Executor\n"
           "\t'help' - for help menu\n"
           "\t'user' - show user's info\n"
           "\t'reg' - register new user (user always alone(()\n"
           "\t'exit' - exit from interpreter\n"
           "\t'decrypt' - decrypt user's password by key\n");
}

static void generate_key (uint8_t key[KEY_LENGTH])
{
    for (size_t i = 0; i < KEY_LENGTH; ++i) {
        key[i] = (uint8_t)(rand() % 255);
    }
}

void print_user_info_cmd_process ()
{
    uint8_t username[MAX_USERNAME_LENGTH] = {0};
    uint8_t password[PASSWORD_LENGTH] = {0};
    uint8_t key[KEY_LENGTH] = {0};

    int32_t rv;

    rv = acc_user_get_info (username, password, key);

    if (rv == USER_UNREGISTERED_ERROR) {
        printf("User unregistered\n");
        return;
    }
    if (rv != USER_OK) {
        printf("Something went wrong.\n");
        return;
    }

    puts("===User info===\n");
    printf("Username: %s\n", username);

    printf("Encrypted password: ");

    for (size_t i = 0; i < PASSWORD_LENGTH; ++i) {
        printf("%02x ", password[i]);
    }
    puts("\n");

    printf("Key (Hash): \n");

    for (size_t i = 0; i < KEY_LENGTH; ++i) {
        printf("%02x ", key[i]);
    }
    puts("\n=============\n");
}

static void register_cmd_process () {
    char * username = NULL;
    char * password = NULL;
    uint8_t key[KEY_LENGTH] = {0};

    if (acc_user_is_registered()) {
        printf("User already registered\n");
        return;
    }

    printf("Register process:\nUsername: ");
    username = readline("");

    printf("Password: ");
    password = getpass("");

    generate_key (key);

    if (acc_create_user (username, password, key) != USER_OK) {
        puts("Can't register user\n");
    } else {
        puts("Your decryption key:\n");
        for (size_t i = 0; i < KEY_LENGTH; ++i) {
            printf("%02x ", key[i]);
        }
        puts("\n\nRemember it, you won't see it again.\n");
    }

    free(username);
    free(password);
}

static int32_t parse_key (const char * key, uint8_t result[KEY_LENGTH])
{
    size_t key_length;
    char *kptr = key;
    int k = 0;

    if (!acc_user_is_registered()) {
        puts("User unregistered\n");
        return -1;
    }
    key_length = strnlen(key, 128);
    if (key_length == 128) {
        puts("Bad key\n");
        return -1;
    }

    while ((kptr != NULL) && (k < KEY_LENGTH)) {
        result[k] = strtol(kptr, &kptr, 16);
        ++k;
    }
    if (k != KEY_LENGTH) {
        return -1;
    }

    return 0;
}

static void decrypt_password_cmd_process ()
{
    char * ent_key = NULL;
    uint8_t key[KEY_LENGTH];
    uint8_t decrypted_pass[PASSWORD_LENGTH];

    printf("Enter your key: ");
    ent_key = readline("");

    if (parse_key(ent_key, key) != 0) {
        free(ent_key);
        return;
    }

    if (acc_decrypt_user_password (key, decrypted_pass) != USER_OK) {
        free(ent_key);
        return;
    }

    printf("Decrypted password: %s\n", decrypted_pass);

    free(ent_key);
}


static COMMAND_TYPE_T get_command_type (char * command)
{
    if (strncmp(command, "exit", 4) == 0) {
        return EXIT_CMD;
    } else if (strncmp(command, "reg", 3) == 0) {
        return REGISTER_CMD;
    } else if (strncmp(command, "help", 4) == 0) {
        return HELP_CMD;
    } else if (strncmp(command, "user", 4) == 0) {
        return PRINT_USER_INFO_CMD;
    } else if (strncmp(command, "decrypt", 7) == 0) {
        return DECRYPT_PASSWORD_CMD;
    } else {
        return UNDEFINED_CMD;
    }
}

static void process_cmd (char * command)
{
    if (command == NULL) {
        return;
    }
    COMMAND_TYPE_T type = get_command_type(command);
    switch (type) {
        case EXIT_CMD:
            PROGRAM_MUST_EXIT = 1;
            acc_free_user();
            break;
        case REGISTER_CMD:
            register_cmd_process();
            break;
        case HELP_CMD:
            help_cmd_process();
            break;
        case PRINT_USER_INFO_CMD:
            print_user_info_cmd_process ();
            break;
        case DECRYPT_PASSWORD_CMD:
            decrypt_password_cmd_process ();
            break;
        case UNDEFINED_CMD:
            puts( "Undefined cmd");
            break;
    }

}

int main (int argc, char * argv[])
{
    char* buf = NULL;

    puts("\nWelcome to the best program ever. \n"
           "To familiarize yourself with the list of commands, type help.\n");

    while (!PROGRAM_MUST_EXIT && (buf = readline(">> ")) != NULL) {
        process_cmd(buf);
        free(buf);
    }

}
