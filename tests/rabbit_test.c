#include <stdio.h>
#include "rabbit.h"

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
  const char * char_keys[3] =
    {"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
     "91 28 13 29 2E 3D 36 FE 3B FC 62 F1 DC 51 C3 AC",
     "83 95 74 15 87 E0 C7 33 E9 E9 AB 01 C0 9B 00 43" };

  int i, j;
  for(i = 0; i < 3; ++i)
    {
      uint8_t key[16];

      key_from_str(key, char_keys[i], 16);

      rabbit_state state;
      rabbit_init_master(&state, key);

      print_vals("key ", key, 16);

      for(j = 0; j < 3; ++j)
	{
	  uint8_t s[16];
	  char name[5];

	  rabbit_extract(&state, s);

	  snprintf(name, 5, "S[%d]", j);
	  print_vals(name, s, 16);
	}
      putchar('\n');
    }

  uint8_t mkey[16];
  key_from_str(mkey, char_keys[0], 16);
  
  const char *ivs[3] =
    {"00 00 00 00 00 00 00 00",
     "C3 73 F5 75 C1 26 7E 59",
     "A6 EB 56 1A D2 F4 17 27" };

  rabbit_state mstate;
  rabbit_init_master(&mstate, mkey);
  print_vals("mkey", mkey, 16);

  for(i = 0; i < 3; ++i)
    {
      rabbit_state ivstate;
      uint8_t iv[8];
      key_from_str(iv, ivs[i], 8);
      print_vals("iv  ", iv, 8);

      rabbit_init_iv(&ivstate, &mstate, iv);

      for(j = 0; j < 3; ++j)
	{
	  uint8_t s[16];
	  char name[5];

	  rabbit_extract(&ivstate, s);

	  snprintf(name, 5, "S[%d]", j);
	  print_vals(name, s, 16);
	}
      putchar('\n');
    }
}
