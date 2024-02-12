#ifndef AES_CRYPT_TRANSFORMATIONS_H
#define AES_CRYPT_TRANSFORMATIONS_H


void fill_key_sequence (uint8_t initial_key[4][4], uint8_t key_sequence[10][4][4]);

void sub_bytes (uint8_t state[4][4]);
void inv_sub_bytes (uint8_t state[4][4]);

void shift_rows (uint8_t state[4][4]);
void inv_shift_rows (uint8_t state[4][4]);

void mix_columns(uint8_t state[4][4]);
void inv_mix_columns(uint8_t state[4][4]);

void add_round_key (uint8_t state[4][4], uint8_t key[4][4]);


#endif
