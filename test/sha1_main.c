/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -I../include -Wextra -Wall -g -O2  -o sha1_main sha1_main.c ../src/sha1_rng.c -lssl -lcrypto
mkdir -p /tmp/tmpfs
sudo mount -t tmpfs -o size=20m tmpfs /tmp/tmpfs
./sha1_main > /tmp/tmpfs/a

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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <error.h>


#include <csprng/sha1_rng.h>

int main(void)
{
  SHA1_state* state;
  uint8_t seed[SHA1_VECTOR_LENGTH_IN_BYTES]={0};
  uint8_t* buf;
  int rc;
  const int size = 4096;

  buf = malloc( size * sizeof(uint8_t));
  state = create_SHA1(seed, SHA1_VECTOR_LENGTH_IN_BYTES, 0, 20);

  while(1) {
    generate_using_SHA1 (state, buf, size);
    rc = fwrite(buf, sizeof(uint8_t), size, stdout);
    if ( rc < size ) {
      fprintf(stderr, "ERROR: fwrite '%s' - bytes written %d, bytes to write %d, errno %d\n",
          "stdout", rc, size, errno);
      error(EXIT_FAILURE, errno, "ERROR: fwrite");
    }

  }

  free(buf);
  destroy_SHA1(state);
  return 0;
}

