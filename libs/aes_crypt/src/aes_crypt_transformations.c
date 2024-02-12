#include <stdint.h>
#include <string.h>

#include "aes_crypt_transformations.h"
#include "aes_constant_values.h"
#include "aes_math.h"

#define LNIBBLE(x) ((x) & 0xf)
#define MNIBBLE(x) (LNIBBLE((x) >> 4))

static inline uint8_t get_mapped_box_value (uint8_t num, const uint8_t box[256])
{
    return box[MNIBBLE((num)) * 16 + LNIBBLE((num))];
}

static void sub_bytes_executor (uint8_t state[4][4], const uint8_t box[256])
{
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = get_mapped_box_value(state[i][j], box);
        }
    }
}

static void shift_row_once_left (uint8_t state[4][4], size_t row)
{
    uint8_t tmp_value = state[row][0];
    for (size_t i = 0; i < 3; ++i) {
        state[row][i] = state[row][i + 1];
    }
    state[row][3] = tmp_value;
}

static void shift_row_once_right (uint8_t state[4][4], size_t row)
{
    uint8_t tmp_value = state[row][3];
    for (size_t i = 3; i > 0; --i) {
        state[row][i] = state[row][i - 1];
    }
    state[row][0] = tmp_value;
}

static void shift_rows_executor (uint8_t state[4][4], void (*shift_func)(uint8_t[4][4], size_t row))
{
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < i; ++j) {
            shift_func(state, i);
        }
    }
}

static void mix_columns_executor (uint8_t state[4][4], const uint8_t mmatrix[4][4])
{
    uint8_t result[4][4];

    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 4; j++) {
            result[i][j] = 0;
            for (size_t k = 0; k < 4; k++) {
                result[i][j] = gadd(
                        gmul(mmatrix[i][k], state[k][j]),
                        result[i][j]
                );
            }
        }
    }
    for (size_t i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 4; ++j) {
            state[i][j] = result[i][j];
        }
    }
}


static void rot_word (uint8_t key[4][4], uint8_t new_column[4])
{
    new_column[3] = key[0][3];
    for (size_t i = 0; i < 3; ++i) {
        new_column[i] = key[i + 1][3];
    }
}


static void key_schedule (uint8_t key[4][4], size_t ircon, uint8_t new_key[4][4])
{
    uint8_t wcolumn[4] = {0};
    rot_word (key, wcolumn);
    for (size_t i = 0; i < 4; ++i) {
        wcolumn[i] = get_mapped_box_value(wcolumn[i], S_BOX);
    }

    new_key[0][0] = key[0][0] ^ wcolumn[0] ^ RCON[ircon];
    new_key[1][0] = key[1][0] ^ wcolumn[1];
    new_key[2][0] = key[2][0] ^ wcolumn[2];
    new_key[3][0] = key[3][0] ^ wcolumn[3];

    for (size_t i = 1; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            new_key[j][i] = key[j][i] ^ new_key[j][i - 1];
        }
    }
}

void fill_key_sequence (uint8_t initial_key[4][4], uint8_t key_sequence[10][4][4])
{
    key_schedule(initial_key, 0, key_sequence[0]);
    for (size_t i = 1; i < 10; ++i) {
        key_schedule(key_sequence[i - 1], i, key_sequence[i]);
    }
}

void sub_bytes (uint8_t state[4][4])
{
    sub_bytes_executor (state, S_BOX);
}

void inv_sub_bytes (uint8_t state[4][4])
{
    sub_bytes_executor (state, INV_S_BOX);
}

void inv_shift_rows(uint8_t state[4][4])
{
    shift_rows_executor(state, shift_row_once_right);
}

void shift_rows (uint8_t state[4][4])
{
    shift_rows_executor(state, shift_row_once_left);
}

void mix_columns(uint8_t state[4][4])
{
    mix_columns_executor(state, MIX_MATRIX);
}


void inv_mix_columns(uint8_t state[4][4])
{
    mix_columns_executor(state, INV_MIX_MATRIX);
}


void add_round_key (uint8_t state[4][4], uint8_t key[4][4])
{
    for (size_t i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] ^= key[i][j];
        }
    }
}