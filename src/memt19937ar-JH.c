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

#include <csprng/memt19937ar-JH.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

/* mag01[x] = x * MEMT_MATRIX_A  for x=0,1 */
static uint32_t mag01[2]={0x0, MEMT_MATRIX_A};

/*plot type*/
static uint32_t case_1(memt_type* state);
static uint32_t case_2(memt_type* state);
static uint32_t case_3(memt_type* state);
static uint32_t case_4(memt_type* state);
static uint32_t case_5(memt_type* state);
static uint32_t case_6(memt_type* state);
static uint32_t case_7(memt_type* state);


/* initializes mt[N] with a seed */
memt_type* MEMT_init_genrand(uint32_t s)
{
  int mti;
  memt_type* state;

  state = calloc(1, sizeof(memt_type));
  if ( state == NULL ) {
    fprintf ( stderr, "MEMT_init_genrand: Dynamic memory allocation failed\n" );
    return state;
  }

  state->kk = 0;

  // state->mt[0]= s & 0xffffffffUL; JH: uint32_t is always 32-bit
  state->mt[0]= s;
  for (mti=1; mti<MEMT_N; mti++) {
    state->mt[mti] = 
      (1812433253UL * (state->mt[mti-1] ^ (state->mt[mti-1] >> 30)) + mti); 
    /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
    /* In the previous versions, MSBs of the seed affect   */
    /* only MSBs of the array mt[].                        */
    /* 2002/01/09 modified by Makoto Matsumoto             */
    //state->mt[mti] &= 0xffffffffUL;  JH: uint32_t is always 32-bit
    /* for >32 bit machines */
  }
  state->genrand_int32 = case_1;
  return state;
}

/* initialize by an array with array-length */
/* init_key is the array for initializing keys */
/* key_length is its length */
/* slight change for C++, 2004/2/26 */
memt_type* MEMT_init_by_array(uint32_t init_key[], int key_length)
{
  int i, j, k;
  memt_type* state;

  state = MEMT_init_genrand(19650218UL);
  if ( state == NULL ) return state;

  i=1; j=0;
  k = (MEMT_N>key_length ? MEMT_N : key_length);
  for (; k; k--) {
    state->mt[i] = (state->mt[i] ^ ((state->mt[i-1] ^ (state->mt[i-1] >> 30)) * 1664525UL))
      + init_key[j] + j; /* non linear */
    // state->mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */ JH: uint32_t is always 32-bit
    i++; j++;
    if (i>=MEMT_N) { state->mt[0] = state->mt[MEMT_N-1]; i=1; }
    if (j>=key_length) j=0;
  }
  for (k=MEMT_N-1; k; k--) {
    state->mt[i] = ( state->mt[i] ^ (( state->mt[i-1] ^ ( state->mt[i-1] >> 30)) * 1566083941UL)) - i; /* non linear */
    //state->mt[i] &= 0xffffffffUL; /* for WORDSIZE > 32 machines */ JH: uint32_t is always 32-bit
    i++;
    if (i>=MEMT_N) {  state->mt[0] =  state->mt[MEMT_N-1]; i=1; }
  }

  state->mt[0] = 0x80000000UL; /* MSB is 1; assuring non-zero initial array */
  state->genrand_int32 = case_1;
  return state;
}

/* Free the memory by destroying memt_type state struct */
void MEMT_destroy(memt_type* state) {
  memset(state, 0, sizeof(state) );
  free(state);
}

static uint32_t case_1(memt_type* state){
  uint32_t y;
  y = (state->mt[state->kk]&MEMT_UPPER_MASK)|(state->mt[state->kk+1]&MEMT_LOWER_MASK);
  state->mt[state->kk] = state->mt[state->kk+MEMT_M] ^ (y >> 1) ^ mag01[y & 0x1];
  y = state->mt[state->kk]^ ((state->mt[state->kk+224] << 14) & 0x3cd68000) ^ ((state->mt[state->kk+124] << 3) & 0x576bad28) ^ ((state->mt[state->kk+24] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y);
  y ^= MEMT_TEMPERING_SHIFT_S(y);
  y ^= (state->mt[state->kk+324] & 0x09040000);		
  state->kk++;
  if(state->kk==MEMT_N-MEMT_M) state->genrand_int32 = case_2;
  return y;
}

static uint32_t case_2(memt_type* state){
  uint32_t y;
  y = (state->mt[state->kk]&MEMT_UPPER_MASK)|(state->mt[state->kk+1]&MEMT_LOWER_MASK);
  state->mt[state->kk] = state->mt[state->kk+(MEMT_M-MEMT_N)] ^ (y >> 1) ^ mag01[y & 0x1];
  y = state->mt[state->kk]^ ((state->mt[state->kk+224] << 14) & 0x3cd68000) ^ ((state->mt[state->kk+124] << 3) & 0x576bad28) ^ ((state->mt[state->kk+24] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y); y ^= MEMT_TEMPERING_SHIFT_S(y);
  y ^= (state->mt[state->kk+324] & 0x09040000);
  state->kk++;
  if(state->kk==300)state->genrand_int32 = case_3;
  return y;
}
			
static uint32_t case_3(memt_type* state){
  uint32_t y;
  y = (state->mt[state->kk]&MEMT_UPPER_MASK)|(state->mt[state->kk+1]&MEMT_LOWER_MASK);
  state->mt[state->kk] = state->mt[state->kk+(MEMT_M-MEMT_N)] ^ (y >> 1) ^ mag01[y & 0x1];
  y=state->mt[state->kk]^ ((state->mt[state->kk+224] << 14) & 0x3cd68000) ^ ((state->mt[state->kk+124] << 3) & 0x576bad28) ^ ((state->mt[state->kk+24] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y); y ^= MEMT_TEMPERING_SHIFT_S(y);
  y ^= (state->mt[state->kk-300] & 0x09040000);
  state->kk++;
  if(state->kk==400)state->genrand_int32 = case_4;
  return y;
}
		
static uint32_t case_4(memt_type* state){
  uint32_t y;
  y = (state->mt[state->kk]&MEMT_UPPER_MASK)|(state->mt[state->kk+1]&MEMT_LOWER_MASK);
  state->mt[state->kk] = state->mt[state->kk+(MEMT_M-MEMT_N)] ^ (y >> 1) ^ mag01[y & 0x1];
  y=state->mt[state->kk]^ ((state->mt[state->kk-400] << 14) & 0x3cd68000) ^ ((state->mt[state->kk+124] << 3) & 0x576bad28) ^ ((state->mt[state->kk+24] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y); y ^= MEMT_TEMPERING_SHIFT_S(y);
  y ^= (state->mt[state->kk-300] & 0x09040000);
  state->kk++;
  if(state->kk==500)state->genrand_int32 = case_5;
  return y;
}
		
static uint32_t case_5(memt_type* state){
  uint32_t y;
  y = (state->mt[state->kk]&MEMT_UPPER_MASK)|(state->mt[state->kk+1]&MEMT_LOWER_MASK);
  state->mt[state->kk] = state->mt[state->kk+(MEMT_M-MEMT_N)] ^ (y >> 1) ^ mag01[y & 0x1];
  y=state->mt[state->kk]^ ((state->mt[state->kk-400] << 14) & 0x3cd68000) ^ ((state->mt[state->kk-500] << 3) & 0x576bad28) ^ ((state->mt[state->kk+24] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y); y ^= MEMT_TEMPERING_SHIFT_S(y);
  y  = y ^ (state->mt[state->kk-300] & 0x09040000);
  state->kk++;
  if(state->kk==600)state->genrand_int32 = case_6;
  return y;
}
		
static uint32_t case_6(memt_type* state){
  uint32_t y;
  y = (state->mt[state->kk]&MEMT_UPPER_MASK)|(state->mt[state->kk+1]&MEMT_LOWER_MASK);
  state->mt[state->kk] = state->mt[state->kk+(MEMT_M-MEMT_N)] ^ (y >> 1) ^ mag01[y & 0x1];
  y=state->mt[state->kk]^ ((state->mt[state->kk-400] << 14) & 0x3cd68000) ^ ((state->mt[state->kk-500] << 3) & 0x576bad28) ^ ((state->mt[state->kk-600] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y); y ^= MEMT_TEMPERING_SHIFT_S(y);
  y  = y ^ (state->mt[state->kk-300] & 0x09040000);
  state->kk++;
  if(state->kk==MEMT_N-1)state->genrand_int32 = case_7;
  return y;
}

static uint32_t case_7(memt_type* state){
  uint32_t y;
  y = (state->mt[MEMT_N-1]&MEMT_UPPER_MASK)|(state->mt[0]&MEMT_LOWER_MASK);
  state->mt[MEMT_N-1] = state->mt[MEMT_M-1] ^ (y >> 1) ^ mag01[y & 0x1];
  y=state->mt[state->kk]^ ((state->mt[state->kk-400] << 14) & 0x3cd68000) ^ ((state->mt[state->kk-500] << 3) & 0x576bad28) ^ ((state->mt[state->kk-600] << 18) & 0xd6740000);
  y ^= MEMT_TEMPERING_SHIFT_U(y); y ^= MEMT_TEMPERING_SHIFT_S(y);
  y  = y ^ (state->mt[state->kk-300] & 0x09040000);
  state->kk=0;
  state->genrand_int32 = case_1;
  return y;
}

/* generates a random number on [0,0xffffffff]-interval */
static inline uint32_t MEMT_genrand_int32_inline(memt_type* state)
{
  return (uint32_t)(state->genrand_int32(state));
}

/* generates a random number on [0,0xffffffff]-interval */
uint32_t MEMT_genrand_int32(memt_type* state)
{
  return (uint32_t)(state->genrand_int32(state));
}


int MEMT_fill_buffer (memt_type* state, uint32_t *output_buffer, int output_size) {
//  Total size of buffer in Bytes = output_size * sizeof(uint32_t) = output_size * 4
//  It will return number of generated uint32_t blocks.

  int i;
  
  for ( i=0; i<output_size; ++i ) {
    *output_buffer = MEMT_genrand_int32_inline(state);
    ++output_buffer;
  }

  return i;
}

  /* generates a random number on [0,0x7fffffff]-interval */
uint32_t MEMT_genrand_int31(memt_type* state)
{
    return (uint32_t)(state->genrand_int32(state)>>1);
}

/* generates a random number on [0,1]-real-interval */
double MEMT_genrand_real1(memt_type* state)
{
    return MEMT_genrand_int32_inline(state)*(1.0/4294967295.0); 
    /* divided by 2^32-1 */ 
}

/* generates a random number on [0,1)-real-interval */
double MEMT_genrand_real2(memt_type* state)
{
    return MEMT_genrand_int32_inline(state)*(1.0/4294967296.0); 
    /* divided by 2^32 */
}

/* generates a random number on (0,1)-real-interval */
double MEMT_genrand_real3(memt_type* state)
{
    return (((double)MEMT_genrand_int32_inline(state)) + 0.5)*(1.0/4294967296.0); 
    /* divided by 2^32 */
}

/* generates a random number on [0,1) with 53-bit resolution*/
double MEMT_genrand_res53(memt_type* state) 
{ 
    uint32_t a=MEMT_genrand_int32_inline(state)>>5, b=MEMT_genrand_int32_inline(state)>>6; 
    return(a*67108864.0+b)*(1.0/9007199254740992.0); 
} 
/* These real versions are due to Isaku Wada, 2002/01/09 added */


