#include <stdio.h>
#include "sosemanuk.h"

static void
key_from_str(uint8_t *key, const char* str, int len)
{
  int j;
  for(j = 0; j < len; ++j)
    {
      unsigned int tmp;
      sscanf(str + 3*j, "%X", &tmp);
      key[len-j-1] = tmp;
    }
}

static void
print_vals(const char *name, const uint8_t *vals, int len)
{
  printf("     %s = [%02X", name, vals[len-1]);
  int j;
  for(j = len-2; j >= 0; --j)
    {
      printf(" %02X", vals[j]);
    }
  puts("]");
}

int main()
{
  uint8_t mkey[] = { 0xA7, 0xC0, 0x83, 0xFE, 0xB7 };
  
  uint8_t iv[] = { 0x00, 0x11, 0x22, 0x33,
		   0x44, 0x55, 0x66, 0x77, 
		   0x88, 0x99, 0xAA, 0xBB,
		   0xCC, 0xDD, 0xEE, 0xFF };

  sosemanuk_master_state mstate;
  sosemanuk_init_key(&mstate, mkey, 40);

  sosemanuk_state ivstate;
  sosemanuk_init_iv(&ivstate, &mstate, iv);

  uint8_t s[16];
  sosemanuk_extract(&ivstate, s);
  print_vals("res", s, 16);

}
