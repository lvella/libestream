#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

int listening = 0;
struct in_addr ip;

static int parse_args(int argc, char *argv[])
{
  if(argc < 4)
    return 0;

  if(!strcmp(argv[1], "-l")) {
      listening = 1;
      if(argc == 5) {
	  ip = inet_addr(argv[2]);
      }
      // TODO: to be continued...
  }
}

int main(int argc, char *argv[])
{

  fprintf(stderr, "Incorrect parameters!\n"
      "Usage for server:\n  %1$s -l [<address>] <port> <hex_key>\n"
      "usage for client:\n  %1$s <address> <port> <hex_key>\n", argv[0]);
}
