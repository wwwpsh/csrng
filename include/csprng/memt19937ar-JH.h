/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* 
This is a maximally equidistributed Mersenne Twister MEMT19937 by Shin Harase (2012/10/9).

Copyright (C) 2012-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>
Copyright (C) 2012 Shin Harase
Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura

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

*/




/* 
This is a maximally equidistributed Mersenne Twister MEMT19937 by Shin Harase (2010/1/25).

Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura
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

Any feedback is very welcome.
http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
email: hladky DOT jiri AT gmail DOT com
*/

#ifndef MEMT_H
#define MEMT_H

#include <inttypes.h>

/* Period parameters */  
#define MEMT_N 624
#define MEMT_M 397
#define MEMT_SIZE_X 19937
#define MEMT_MATRIX_A 0x9908b0dfU   /* constant vector a */
#define MEMT_UPPER_MASK 0x80000000U /* most significant w-r bits */
#define MEMT_LOWER_MASK 0x7fffffffU /* least significant r bits */

/* Tempering parameters */   
#define MEMT_TEMPERING_SHIFT_U(y)  (y >> 11)
#define MEMT_TEMPERING_SHIFT_S(y)  (y << 7)

typedef struct memt_type memt_type;

struct memt_type {
  uint32_t mt[MEMT_N];                     /* the array for the state vector  */
  int kk;
  int (*func)(int a, float b);
  uint32_t (*genrand_int32)(memt_type* state);             /* Pointer to function returning uint32_t*/
};

/* initializes mt[MEMT_N] with a seed */
memt_type* MEMT_init_genrand(uint32_t s);

/* initialize by an array with array-length */
/* init_key is the array for initializing keys */
/* key_length is its length */
/* slight change for C++, 2004/2/26 */
memt_type* MEMT_init_by_array(uint32_t init_key[], int key_length);

/* Free the memory by destroying memt_type state struct */
void MEMT_destroy(memt_type* state);

/* generates a random number on [0,0xffffffff]-interval */
uint32_t MEMT_genrand_int32(memt_type* state);

/* Fill the buffer output_buffer with output_size uint32_t blocks
 * Size of the buffer has to be at least 4 * output_size bytes
 * Returns number of generated uint32_t blocks (should be same as output_size) */
int MEMT_fill_buffer (memt_type* state, uint32_t *output_buffer, int output_size);

/* generates a random number on [0,0x7fffffff]-interval */
uint32_t MEMT_genrand_int31(memt_type* state);

/* generates a random number on [0,1]-real-interval */
double MEMT_genrand_real1(memt_type* state);

/* generates a random number on [0,1)-real-interval */
double MEMT_genrand_real2(memt_type* state);

/* generates a random number on (0,1)-real-interval */
double MEMT_genrand_real3(memt_type* state);

/* generates a random number on [0,1) with 53-bit resolution*/
double MEMT_genrand_res53(memt_type* state);
/* These real versions are due to Isaku Wada, 2002/01/09 added */

#endif
