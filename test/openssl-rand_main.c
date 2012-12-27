/*
gcc -I../include -Wextra -Wall -g -O2  -o openssl-rand_main openssl-rand_main.c -lcrypto
mkdir -p /tmp/tmpfs
sudo mount -t tmpfs -o size=20m tmpfs /tmp/tmpfs
./openssl-rand_main > /tmp/tmpfs/a
*/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <error.h>

#include <openssl/rand.h>

int main(void)
{
  int rc;
  uint8_t* buf;
  const int size = 4096;

  if (RAND_get_rand_method() == NULL) RAND_set_rand_method(RAND_SSLeay());

  buf = malloc(size * sizeof(uint8_t));
  if ( buf == NULL ) return 1;

  while(1) {
    if ( RAND_bytes(buf, size) == 0 ) return 1;
    rc = fwrite(buf, sizeof(uint8_t), size, stdout);
    if ( rc < size ) {
      fprintf(stderr, "ERROR: fwrite '%s' - bytes written %d, bytes to write %d, errno %d\n",
        "stdout", rc, size, errno);
      error(EXIT_FAILURE, errno, "ERROR: fwrite");
    }
  }

  free(buf);
  return 0;
}

