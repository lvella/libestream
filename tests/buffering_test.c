#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include "buffered.h"
#include "util.h"

uint8_t stream_a[20000000];
uint8_t stream_b[20000000];

int main()
{
  srand(time(NULL));

  uint8_t key[16];

  int i;
  for(i = 0; i < 16; ++i)
    key[i] = rand() % 256;

  rabbit_state state1;
  rabbit_init_key(&state1, key);

  rabbit_state_buffered state2, state3;
  state3.state = state2.state = state1;
  state3.available_count = state2.available_count = 0;

  /* Reference extraction. */
  for(i = 0; i < 20000000; i+=16)
    rabbit_extract(&state1, &stream_a[i]);

  uint8_t digest = 0;
  for(i = 0; i < 20000000; ++i)
    {
      digest |= stream_a[i];
    }
  printf("unbuffered extract digest: %02X\n", digest);

  /* Buffered extraction. */
  size_t done = 0;
  while(done < 20000000)
    {
      for(i = 1; i < 512; ++i)
	{
	  size_t len = min(i, 20000000 - done);
	  buffered_action(&rabbit_cipher, &state2, &stream_b[done], len, BUFFERED_EXTRACT);
	  done += len;
	}
    }

  if(memcmp(stream_a, stream_b, 20000000))
    {
      puts("buffered extract failed, differ!\n");
      exit(1);
    }

  /* Buffered ecryption. */
  done = 0;
  while(done < 20000000)
    {
      for(i = 1; i < 512; ++i)
	{
	  size_t len = min(i, 20000000 - done);
	  buffered_action(&rabbit_cipher, &state3, &stream_a[done], len, BUFFERED_ENCDEC);
	  done += len;
	}
    }

  digest = 0;
  for(i = 0; i < 20000000; ++i)
    {
      digest |= stream_a[i];
    }

  printf("buffered enc digest: %02X\n", digest);

  if(digest)
    {
      puts("buffered extract failed!");
      exit(1);
    }

  puts("success!");
}
