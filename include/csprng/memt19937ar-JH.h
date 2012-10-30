/* 
   Adapted by Jiri Hladky, hladky DOT jiri AT gmail DOT com

   This is a maximally equidistributed Mersenne Twister MEMT19937 by Shin Harase (2010/1/25).

   A C-program for MT19937, with initialization improved 2002/1/26.
   Coded by Takuji Nishimura and Makoto Matsumoto.

   Before using, initialize the state by using init_genrand(seed)  
   or init_by_array(init_key, key_length).

   Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
   All rights reserved.                          

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

     3. The names of its contributors may not be used to endorse or promote 
        products derived from this software without specific prior written 
        permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


   Any feedback is very welcome.
   http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
   email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
*/

#ifndef MEMT_H
#define MEMT_H

#include <inttypes.h>

/* Period parameters */  
#define MEMT_N 624
#define MEMT_M 397
#define MEMT_SIZE_X 19937
#define MEMT_MATRIX_A 0x9908b0df   /* constant vector a */
#define MEMT_UPPER_MASK 0x80000000 /* most significant w-r bits */
#define MEMT_LOWER_MASK 0x7fffffff /* least significant r bits */

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
