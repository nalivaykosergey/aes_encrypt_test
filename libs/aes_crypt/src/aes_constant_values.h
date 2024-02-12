#ifndef SBS_AES_CONSTANT_VALUES_H
#define SBS_AES_CONSTANT_VALUES_H

#include <stdint.h>

extern const uint8_t S_BOX[256];
extern const uint8_t INV_S_BOX[256];
extern const uint8_t RCON[14];
extern const uint8_t MIX_MATRIX[4][4];
extern const uint8_t INV_MIX_MATRIX[4][4];

#endif
