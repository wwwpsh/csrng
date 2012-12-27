/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -I ../include -Wextra -Wall -o memt_main memt_main.c ../src/memt19937ar-JH.c
./memt_main | head -c 10000000 | sha1sum

gcc -I ../include -L../src/.libs -Wextra -Wall -o memt_main memt_main.c -lcsprng
LD_LIBRARY_PATH=../src/.libs ./memt_main

mkdir -p /tmp/tmpfs
sudo mount -t tmpfs -o size=20m tmpfs /tmp/tmpfs
./memt_main > /tmp/tmpfs/a

*/

/* {{{ Copyright notice
Copyright (C) 2011, 2012 Jirka Hladky

This file is part of CSRNG http://code.google.com/p/csrng/

CSRNG is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CSRNG is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with CSRNG.  If not, see <http://www.gnu.org/licenses/>.
}}} */

#include <csprng/memt19937ar-JH.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>
#include <error.h>

int main(void)
{
  int rc;
  memt_type* memt;
  uint32_t init[4]={0x123, 0x234, 0x345, 0x456}, length=4;
  memt = MEMT_init_by_array(init, length);

#if 0
  int i;
  printf("1000 outputs of genrand_int32(state)\n");
  for (i=0; i<1000; i++) {
    printf("%10"PRIu32" ", MEMT_genrand_int32(memt));
    if (i%5==4) printf("\n");
  }
  printf("\n1000 outputs of genrand_real2(state)\n");
  for (i=0; i<1000; i++) {
    printf("%10.8f ", MEMT_genrand_real2(memt));
    if (i%5==4) printf("\n");
  }
#endif

#if 1
  int i;
  uint32_t* buf;
  uint32_t* pos;
  const int N = 1024;

  buf = malloc(N * sizeof(uint32_t));
  pos = buf;


  while(1) {
    for( i = 0; i < N; ++i) {
      *pos = MEMT_genrand_int32(memt);
      pos++;
    }
    pos = buf;
    rc = fwrite(buf, sizeof(uint32_t), N, stdout);
    if ( rc < N ) {
      fprintf(stderr, "ERROR: fwrite '%s' - bytes written %d, bytes to write %d, errno %d\n",
          "stdout", rc * (int) sizeof(uint32_t), N * (int) sizeof(uint32_t), errno);
      error(EXIT_FAILURE, errno, "ERROR: fwrite");
    }
  }
  free(buf);
#endif   

#if 0
  int i;
  uint32_t* buf;

  buf = malloc(1024*sizeof(uint32_t));

  while(1) {
    i = MEMT_fill_buffer(memt, buf, 1024);
    assert(i == 1024);

    fwrite(buf, sizeof(uint32_t), 1024, stdout);
  }
  free(buf);
#endif   



#if 0
  uint32_t buf;
  while(1) {
    buf = MEMT_genrand_int32(memt);
    fwrite( (void *) (&buf), sizeof(uint32_t), 1, stdout);
  }
#endif
  MEMT_destroy(memt);
  return 0;
}


