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

  rabbit_buffered_state state2, state3;

  state2 = state3 = rabbit_static_initializer;
  state3.state = state2.state = state1;

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
	  buffered_action((buffered_state *)&state2, &stream_b[done], len, BUFFERED_EXTRACT);
	  done += len;
	}
    }

  if(memcmp(stream_a, stream_b, 20000000))
    {
      puts("buffered extract failed, differ!");
      exit(1);
    }
  else
    puts("buffered extract successful, matches unbuffered reference!");

  /* Buffered ecryption. */
  done = 0;
  while(done < 20000000)
    {
      for(i = 1; i < 512; ++i)
	{
	  size_t len = min(i, 20000000 - done);
	  buffered_action((buffered_state *)&state3, &stream_a[done], len, BUFFERED_ENCDEC);
	  done += len;
	}
    }

  digest = 0;
  for(i = 0; i < 20000000; ++i)
    {
      digest |= stream_a[i];
    }

  printf("buffered enc/dec digest: %02X\n", digest);

  if(digest)
    {
      puts("buffered enc/dec failed!");
      exit(1);
    }
  else
    puts("buffered enc/dec successful, all zero!");


  puts("success!");
}
