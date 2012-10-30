/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -I../include -L../src/.libs -Wextra -Wall -g -O2  -o qrbg_main qrbg_main.c -lcsprng
QRBG_USER=jirka QRBG_PASSWD=KLZqym22r0 LD_LIBRARY_PATH=../src/.libs ./qrbg_main
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

#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>

#include <csprng/qrbg-c.h>


int main(void) {
  struct QRBG* p;
  uint8_t *buf;
  char* QRBG_RNG_login_name;       //User name for random.irb.hr
  char* QRBG_RNG_passwd;           //Password for  random.irb.hr

  const size_t buf_size = 1024;
  size_t bytes;
  buf = calloc(buf_size, 1);
  
  
  p = newQRBG();

  defineServerQRBG(p, "random.irb.hr", 1227);

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


  defineUserQRBG(p, QRBG_RNG_login_name, QRBG_RNG_passwd);

  int ret, val;
  ret = getIntQRBG(p, &val);

  fprintf(stderr, "Ret val: %d, Rnd val: %d \n", ret, val);

  bytes = getBytesQRBG(p, buf, buf_size);
  if (bytes < buf_size )  fprintf(stderr, "Requested %zu bytes, got %zu bytes.\n", buf_size, bytes);
  if ( bytes > 0 ) fwrite(buf, bytes, 1, stdout);

  deleteQRBG(p);
  return 0;
}
