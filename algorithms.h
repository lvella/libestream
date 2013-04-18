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
  UHASH_32,
  UHASH_64,
  UHASH_96,
  UHASH_128
} uhash_type;
