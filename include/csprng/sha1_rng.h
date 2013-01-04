/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

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

#ifndef SHA1_RNG_H
#define SHA1_RNG_H

#define SHA1_VECTOR_LENGTH_IN_BYTES 55

#include <inttypes.h>

typedef struct
{
   unsigned char V[SHA1_VECTOR_LENGTH_IN_BYTES];          /* Vector for CTR mode. It holds 440bits. Period is thus 2^440 */
   unsigned char output[20];                              /* Output - 160 bit SHA-1 sum */
   int remove;                                            /* Number of initial bytes dropped */
   int use;                                               /* Number of bytes used */
   int valid;                                             /* number of bytes ready to be used */
   unsigned char* data;
} SHA1_state;

SHA1_state* create_SHA1(uint8_t* seed, int len, int remove, int use);

void destroy_SHA1(SHA1_state* state);

int generate_using_SHA1 (SHA1_state *state, unsigned char *output_buffer, int output_size);

#endif
