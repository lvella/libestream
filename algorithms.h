#pragma once


typedef enum
{
  HC128,
  RABBIT,
  SALSA20,
  SOSEMANUK,
  LAST_CIPHER = SOSEMANUK
} cipher_type;

typedef enum
{
  UHASH_32 = 1,
  UHASH_64 = 2,
  UHASH_96 = 3,
  UHASH_128 = 4
} uhash_type;
