/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -I../include -L../src/.libs -Wextra -Wall -g -O2  -o http_main http_main.c -lcsprng -lpthread -lrt
LD_LIBRARY_PATH=../src/.libs strace -s 256 -ff -o /tmp/a ./http_main | pv > /dev/null
LD_LIBRARY_PATH=../src/.libs valgrind --track-origins=yes --leak-check=full --tool=memcheck --show-reachable=yes --num-callers=20 --track-fds=yes ./http_main
QRBG_USER=..... QRBG_PASSWD=...... LD_LIBRARY_PATH=../src/.libs ./http_main
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
#include <assert.h>
#include <csprng/http_rng.h>
#include <time.h>
#include <errno.h>
#include <error.h>
#include <string.h>


int main(void) {
  int rc;
  http_random_state_t* state;
  uint8_t *buf;
  int buf_size = 1024;
  int num, bytes, bytes_written, bytes_remaining;
  int limit=4096*8;
  int zero_round = 0;
  struct timespec ts[2];
  char* QRBG_RNG_login_name;       //User name for random.irb.hr
  char* QRBG_RNG_passwd;           //Password for  random.irb.hr


  buf = calloc(buf_size, 1);

  QRBG_RNG_login_name = getenv("QRBG_USER");
  QRBG_RNG_passwd     = getenv("QRBG_PASSWD");
  if ( QRBG_RNG_login_name == NULL || QRBG_RNG_passwd == NULL ) {
    fprintf ( stderr, "ERROR: random.irb.hr generators needs login credentials defined in environmental variables QRBG_USER and QRBG_PASSWD.\n" );
    if ( QRBG_RNG_login_name == NULL ) fprintf ( stderr, "WARNING: environmental variable QRBG_USER is not defined.\n");
    if ( QRBG_RNG_passwd == NULL )     fprintf ( stderr, "WARNING: environmental variable QRBG_PASSWD is not defined.\n");
    return 1;
  }

  if ( unsetenv("QRBG_USER") ) fprintf(stderr, "WARNING: unsetenv(\"QRBG_USER\") failed with %s.\n", strerror(errno));
  if ( unsetenv("QRBG_PASSWD") ) fprintf(stderr, "WARNING: unsetenv(\"QRBG_PASSWD\") failed with %s.\n", strerror(errno));

  state = http_random_init(MASK_HOTBITS | MASK_RANDOM_ORG | MASK_RANDOMNUMBERS_INFO | MASK_QRBG, 16384, 1, QRBG_RNG_login_name, QRBG_RNG_passwd);
  //state = http_random_init(MASK_QRBG, 16384, 1, QRBG_RNG_login_name, QRBG_RNG_passwd);
  //state = http_random_init(MASK_HOTBITS, 16384, 1, QRBG_RNG_login_name, QRBG_RNG_passwd);
  //state = http_random_init(MASK_HOTBITS | MASK_RANDOM_ORG | MASK_RANDOMNUMBERS_INFO, 16384, 1, QRBG_RNG_login_name, QRBG_RNG_passwd);
  //state = http_random_init(MASK_RANDOM_ORG, 16384, 1, QRBG_RNG_login_name, QRBG_RNG_passwd);
  //state = http_random_init(MASK_RANDOMNUMBERS_INFO, 16384, 1, QRBG_RNG_login_name, QRBG_RNG_passwd);

  bytes_written = 0;
  bytes_remaining = limit;
  while( bytes_remaining > 0 ) {
    http_random_status(state, 1);

    if ( bytes_remaining > buf_size ) {
      bytes = buf_size;
    } else {
      bytes = bytes_remaining;
    }
    clock_gettime(CLOCK_REALTIME, &ts[0]);
    num = http_random_generate(state, buf, bytes, 20);
    clock_gettime(CLOCK_REALTIME, &ts[1]);
    fprintf(stderr,"main: slept %g seconds\n", (double) ts[1].tv_sec- (double) ts[0].tv_sec + 
        ( (double) ts[1].tv_nsec - (double) ts[0].tv_nsec ) / 1.0e9 );
    fprintf(stderr, "main: got %d bytes\n", num);
    if ( num > 0 ) {
      rc = fwrite(buf, 1, num, stdout);
      //size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
      if ( rc < num ) {
      fprintf(stderr, "ERROR: fwrite '%s' - bytes written %d, bytes to write %d, errno %d\n",
          "stdout", rc, num, errno);
      error(EXIT_FAILURE, errno, "ERROR: fwrite");
      }


      bytes_remaining -= num;
      bytes_written += num;
      zero_round = 0;
    } else {
      ++zero_round;
      if ( zero_round > 2 ) {
        fprintf(stderr, "main: got 0 bytes %d times in row, exiting.\n", zero_round);
        break;
      }
    }
  }

  assert(bytes_remaining+bytes_written == limit);
  assert(bytes_remaining>=0);
  fprintf(stderr, "main: got %d bytes from %d bytes requested\n", bytes_written, limit);

  http_random_destroy(state);
  free(buf);
  if ( limit > 0 ) {
    return 1;
  } else {
    return 0;
  }

}
