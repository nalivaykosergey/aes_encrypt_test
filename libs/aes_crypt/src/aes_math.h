#ifndef SBS_AES_MATH_H
#define SBS_AES_MATH_H

#include <stdint.h>

/* Add two numbers in the GF(2^8) finite field */
extern uint8_t gadd(uint8_t a, uint8_t b);

/* Multiply two numbers in the GF(2^8) finite field defined
 * by the modulo polynomial relation x^8 + x^4 + x^3 + x + 1 = 0
 * (the other way being to do carryless multiplication followed by a modular reduction)
 */
uint8_t gmul(uint8_t a, uint8_t b);

#endif
