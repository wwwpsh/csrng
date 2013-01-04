/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

SHA1 based RNG

Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>

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

#include <csprng/sha1_rng.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <inttypes.h>
#include <assert.h>

static void increment_block(uint8_t V[], int n)
{
  //Increment the output block by one as a big-endian number
  int i;
  for (i = n-1; i >= 0; --i) {
    ++V[i];
    if (V[i] > 0) return;
  }
}

SHA1_state* create_SHA1(uint8_t* seed, int len, int remove, int use) {
  assert(remove < 20);
  assert(remove >= 0);
  assert(use > 0);
  assert(use <= 20 );
  assert(remove + use <= 20);

  if (len > SHA1_VECTOR_LENGTH_IN_BYTES) len = SHA1_VECTOR_LENGTH_IN_BYTES;
  
  SHA1_state* state;
  int i;
  state = calloc(1, sizeof(SHA1_state));
  if ( state == NULL ) {
    fprintf ( stderr, "create_SHA1: Dynamic memory allocation failed\n" );
    return state;
  }

  state->remove = remove;
  state->use = use;
  state->valid = 0;
  state->data = NULL;
  for (i=0; i< len; ++i) state->V[i] = seed[i];
  return state;
}

void destroy_SHA1(SHA1_state* state) {
  memset(state, 0, sizeof(state) );
  free(state);
}

int generate_using_SHA1 (SHA1_state *state, unsigned char *output_buffer, int output_size) {
  int bytes_written=0;
  int bytes_to_produce = output_size;
  unsigned char* ret;

  if ( state->valid == 0 ) {
    ret = SHA1( state->V, SHA1_VECTOR_LENGTH_IN_BYTES, state->output);
    if ( ret != state->output ) { 
      fprintf ( stderr, "ERROR: SHA1 function has failed.\n" );
      return bytes_written;
    }

    increment_block(state->V, SHA1_VECTOR_LENGTH_IN_BYTES);
    state->valid = state->use;
    state->data = state->output + state->remove;
  }

  while ( bytes_written < output_size ) {
    if (  state->valid < bytes_to_produce ) {
      memcpy(output_buffer, state->data, state->valid);
      bytes_written += state->valid;
      output_buffer += state->valid;
      bytes_to_produce -= state->valid;
      //state->valid = 0;
      //state->data = NULL;

      ret = SHA1( state->V, SHA1_VECTOR_LENGTH_IN_BYTES, state->output);
      if ( ret != state->output ) { 
        fprintf ( stderr, "ERROR: SHA1 function has failed.\n" );
        return bytes_written;
      }
      increment_block(state->V, SHA1_VECTOR_LENGTH_IN_BYTES);
      state->valid = state->use;
      state->data = state->output + state->remove;
      

    } else if (  state->valid == output_size ) {
      memcpy(output_buffer, state->data, state->valid);
      state->valid = 0;
      //state->data = NULL;
      return output_size;
    } else {
      memcpy(output_buffer, state->data, bytes_to_produce);
      state->valid -= bytes_to_produce;
      state->data += bytes_to_produce;
      return output_size;
    }
  }
  return output_size;
}

