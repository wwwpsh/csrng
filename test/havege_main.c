/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -g -I ../include -L../src/.libs -Wextra -Wall -o havege_main havege_main.c -lcrypto -lcsprng
LD_LIBRARY_PATH=../src/.libs ./havege_main
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
#include <string.h>
#include <csprng/havege.h>
#include <openssl/sha.h>


/* Would like closed interval [min, max] */
unsigned int random_in_range (unsigned int min, unsigned int max)
{
  unsigned long int base_random = random(); /* in [0, RAND_MAX] */
  unsigned long int range       = max - min + 1,
                    remainder   = ( (unsigned long int) (RAND_MAX) + 1 ) % range,
                    bucket      = ( (unsigned long int) (RAND_MAX) + 1 ) / range;
  /* There are range buckets, plus one smaller interval
     within remainder of RAND_MAX */
  if (base_random > RAND_MAX - remainder) {
    return random_in_range (min, max);
  } else {
    return min + base_random/bucket;
  }
}

void
dump_hex_byte_string (const unsigned char* data, const unsigned int size, const char* message) {
  unsigned int i;
  if (message)
	  fprintf(stderr,"%s",message);

  for (i=0; i<size; ++i) {
	fprintf(stderr,"%02x",data[i]);
  }
  fprintf(stderr,"\n");
}



int main(void) {
  int error;
  DATA_TYPE* buf;

  buf = calloc(HAVEGE_NDSIZECOLLECT, sizeof(DATA_TYPE));

  error = havege_init( 0, 0, 0);
  if ( error ) {
    fprintf(stderr, "ERROR: havege_init has returned %d\n",error);
    return 1;
  }

#if 0
  size_t blocks = 24;
  size_t blocks_to_generate = blocks * HAVEGE_NDSIZECOLLECT;

  unsigned int i;
  SHA_CTX c ;
  unsigned char md1[SHA_DIGEST_LENGTH];
  unsigned char md2[SHA_DIGEST_LENGTH];
  size_t blocks_requested, blocks_generated;

  error = SHA1_Init(&c);
  if ( error != 1 ) {
    fprintf(stderr, "ERROR: SHA1_Init has returned %d\n",error);
    return 1;
  }
  
  for(i=0;i<blocks;++i) {
    error = SHA1_Update(&c, ndrand_full_buffer(), sizeof(DATA_TYPE) * HAVEGE_NDSIZECOLLECT);
    if ( error != 1 ) {
      fprintf(stderr, "ERROR: SHA1_Update has returned %d\n",error);
      return 1;
    }
  }

  error = SHA1_Final(md1, &c);
  if ( error != 1 ) {
    fprintf(stderr, "ERROR: SHA1_Final has returned %d\n",error);
    return 1;
  }
  havege_destroy();

  error = havege_init( 0, 0, 0);
  if ( error ) {
    fprintf(stderr, "ERROR: havege_init has returned %d\n",error);
    return 1;
  }

  error = SHA1_Init(&c);
  if ( error != 1 ) {
    fprintf(stderr, "ERROR: SHA1_Init has returned %d\n",error);
    return 1;
  }

  while ( blocks_to_generate > 0 ) {
    if ( blocks_to_generate > HAVEGE_NDSIZECOLLECT ) {
      blocks_requested = random_in_range(1, HAVEGE_NDSIZECOLLECT);
    } else {
      blocks_requested = random_in_range(1, blocks_to_generate);
    }
    blocks_generated = generate_words_using_havege (buf, blocks_requested);
    if ( blocks_generated != blocks_requested  ) {
      fprintf(stderr,  "ERROR: generate_words_using_havege has returned %zu blocks instead of %zu blocks requested.\n", blocks_generated, blocks_requested);
      return 1;
    }
    blocks_to_generate -= blocks_generated;
    error = SHA1_Update(&c, buf, sizeof(DATA_TYPE) * blocks_generated);
    if ( error != 1 ) {
      fprintf(stderr, "ERROR: SHA1_Update has returned %d\n",error);
      return 1;
    }
  }

  error = SHA1_Final(md2, &c);
  if ( error != 1 ) {
    fprintf(stderr, "ERROR: SHA1_Final has returned %d\n",error);
    return 1;
  }

  dump_hex_byte_string ( md1, sizeof(md1), "SHA-1 sum using ndrand_full_buffer\n" );
  dump_hex_byte_string ( md2, sizeof(md2), "SHA-1 sum using generate_words_using_havege\n" );
#else
#if 0
  size_t blocks_requested, blocks_generated;
  while ( 1 ) {
    blocks_requested = random_in_range(1, HAVEGE_NDSIZECOLLECT);
    blocks_generated = generate_words_using_havege (buf, blocks_requested);
    if ( blocks_generated != blocks_requested  ) {
      fprintf(stderr,  "ERROR: generate_words_using_havege has returned %zu blocks instead of %zu blocks requested.\n", blocks_generated, blocks_requested);
      return 1;
    }
    fwrite(buf, sizeof(DATA_TYPE), blocks_generated, stdout);
  }
#else
  while ( 1 ) {
    //memcpy(buf, ndrand_full_buffer(), HAVEGE_NDSIZECOLLECT * sizeof(DATA_TYPE) );
    //fwrite(buf, sizeof(DATA_TYPE), HAVEGE_NDSIZECOLLECT, stdout);

    fwrite(ndrand_full_buffer(), sizeof(DATA_TYPE), HAVEGE_NDSIZECOLLECT, stdout);
  }

#endif  
#endif

  havege_destroy();
  free(buf);
  return 0;
}


