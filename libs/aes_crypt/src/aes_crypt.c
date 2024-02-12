#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../include/aes_crypt.h"
#include "aes_crypt_transformations.h"


static uint8_t pack_data (const uint8_t * text, size_t text_size, uint8_t packed_data[4][4])
{
    size_t k = 0;
    for (size_t i = 0; i < 4 && k < text_size; ++i) {
        for (size_t j = 0; j < 4 && k < text_size; ++j, ++k) {
            packed_data[j][i] = text[k];
        }
    }
    return AES_CRYPT_OK;
}

static uint8_t unpack_data (uint8_t data[4][4], uint8_t * text)
{
    size_t k = 0;
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j, ++k) {
            text[k] = data[j][i];
        }
    }
    return AES_CRYPT_OK;
}



void hex_dump (const uint8_t * data, size_t data_length, const uint8_t * label)
{
    if (label != NULL) {
        fprintf(stdout, "%s:\n\t", label);
    }
    for (size_t i = 0; i < data_length; ++i) {
        fprintf(stdout, "%x ", data[i]);
    }
    fprintf(stdout, "\n");
}

void print_table(const uint8_t table[4][4], const char * label)
{
    if (label) {
        printf("%s:\n", label);
    }
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            printf("0x%x ", table[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}


static void encrypt (uint8_t state[4][4], uint8_t key[4][4])
{
    const size_t rounds = 10;
    uint8_t key_sequence[10][4][4];
    fill_key_sequence(key, key_sequence);

    add_round_key(state, key);

    for (size_t i = 1; i < rounds; ++i) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, key_sequence[i - 1]);

    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, key_sequence[9]);
}

static void decrypt (uint8_t state[4][4], uint8_t key[4][4])
{
    uint8_t key_sequence[10][4][4];
    fill_key_sequence(key, key_sequence);

    add_round_key(state, key_sequence[9]);
    for (int i = 8; i >= 0; --i) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, key_sequence[i]);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, key);
}


int aes_encrypt (const uint8_t * text, const uint8_t * key, uint8_t * cypher_text)
{


    uint8_t state[4][4] = {0}, pkey[4][4] = {0};

    pack_data(text, 16, state);
    pack_data(key, 16, pkey);

    encrypt(state, pkey);

    unpack_data(state, cypher_text);

    return AES_CRYPT_OK;
}



int aes_decrypt (const uint8_t * cypher_text, const uint8_t * key, uint8_t * text)
{

    uint8_t state[4][4] = {0}, pkey[4][4] = {0};

    pack_data(cypher_text, 16, state);
    pack_data(key, 16, pkey);

    decrypt(state, pkey);
    unpack_data(state, text);

    return AES_CRYPT_OK;
}