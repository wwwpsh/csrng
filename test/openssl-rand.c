/*
gcc -I../include -Wextra -Wall -g -O2  -o openssl-rand openssl-rand.c -lcrypto
*/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openssl/rand.h>

int main(void)
{
  uint8_t* buf;
  if (RAND_get_rand_method() == NULL) RAND_set_rand_method(RAND_SSLeay());

  buf = malloc(4096*sizeof(uint8_t));
  if ( buf == NULL ) return 1;

  while(1) {
    if ( RAND_bytes(buf, 4096) == 0 ) return 1;
    fwrite(buf, sizeof(uint8_t), 4096, stdout);
  }

  free(buf);
  return 0;
}

