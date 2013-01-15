#include <stdio.h>
#include "rabbit.h"

int main()
{
  uint8_t keys[3][16] =
    {{00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00},
     {0x91, 0x28, 0x13, 0x29, 0x2E, 0x3D, 0x36, 0xFE, 0x3B, 0xFC, 0x62, 0xF1, 0xDC, 0x51, 0xC3, 0xAC},
     {0x83, 0x95, 0x74, 0x15, 0x87, 0xE0, 0xC7, 0x33, 0xE9, 0xE9, 0xAB, 0x01, 0xC0, 0x9B, 0x00, 0x43}};

  int i, j, k;
  for(i = 0; i < 3; ++i)
    {
      rabbit_state state;
      rabbit_init_master(&state, keys[i]);

      printf("     key  = [%02X", keys[i][0]);
      for(j = 1; j < 16; ++j)
	{
	  printf(" %02X", keys[i][j]);
	}
      puts("]");

      for(j = 0; j < 3; ++j)
	{
	  uint8_t s[16];
	  rabbit_extract(&state, s);

	  printf("     S[%d] = [%02X", j, s[0]);
	  for(k = 1; k < 16; ++k) {
	    printf(" %02X", s[k]);
	  }
	  puts("]");
	}
      putchar('\n');
    }
}
