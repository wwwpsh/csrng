/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

fips.h -- Performs FIPS 140-1/140-2 tests for RNGs

Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>
Copyright (C) 2001 Philipp Rumpf

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

#ifndef FIPS__H
#define FIPS__H

/*  Size of a FIPS test buffer, do not change this */
#define FIPS_RNG_BUFFER_SIZE 2500

#include <inttypes.h>
#include <time.h>

/*
 * Return values for fips_run_rng_test.  These values are OR'ed together
 * for all tests that failed.
 */
#define FIPS_RNG_MONOBIT	0x0001 /* FIPS 140-2 2001-10-10 monobit */
#define FIPS_RNG_POKER		0x0002 /* FIPS 140-2 2001-10-10 poker */
#define FIPS_RNG_RUNS		0x0004 /* FIPS 140-2 2001-10-10 runs */
#define FIPS_RNG_LONGRUN	0x0008 /* FIPS 140-2 2001-10-10 long run */
#define FIPS_RNG_CONTINUOUS_RUN 0x0010 /* FIPS 140-2 continuous run */

/*
 * Names for the FIPS tests, and bitmask
 */
#define N_FIPS_TESTS 5
extern char const * const fips_test_names[N_FIPS_TESTS];
extern unsigned int const fips_test_mask[N_FIPS_TESTS];

/* FIPS 140-2 statistics */
typedef struct {
	uint64_t bad_fips_blocks;	                //Blocks rejected by FIPS 140-2 
	uint64_t good_fips_blocks;	              //Blocks approved by FIPS 140-2 
	uint64_t fips_failures[N_FIPS_TESTS]; 	  //Breakdown of block failures per FIPS test
  int track_CPU_time;                       //Track CPU time spend on FIPS tests? 0=FALSE, 1=TRUE
  struct timespec cpu_time;                 //CPU time spent on FIPS tests?
} fips_statistics_type;

/* Context for running FIPS tests */
typedef struct fips_ctx {
	int poker[16], runs[12];
	int ones, rlength, current_bit, last_bit, longrun;
	unsigned int last32;
  fips_statistics_type fips_statistics;
} fips_ctx_t;



/* Initializes the context for FIPS tests.  last32 contains
 * 32 bits of RNG data to init the continuous run test */
extern void fips_init(fips_ctx_t *ctx, unsigned int last32, int track_CPU_time);


/*
 *  Runs the FIPS 140-1 4.11.1 and 4.11.2 tests, as updated by
 *  FIPS 140-2 4.9, errata from 2001-10-10 (which set more strict
 *  intervals for the tests to pass), on a buffer of size 
 *  FIPS_RNG_BUFFER_SIZE, using the given context.
 *
 *  FIPS 140-2, errata of 2002-12-03 removed tests for non-deterministic 
 *  RNGs, other than Continuous Run test.
 *  
 *  This funtion returns 0 if all tests passed, or a bitmask
 *  with bits set for every test that failed.
 *
 *  It returns -1 if either ctx or buf is NULL.
 */
int fips_run_rng_test(fips_ctx_t *ctx, const void *buf);

char* dump_fips_statistics ( fips_statistics_type *fips_statistics);

#endif /* FIPS__H */
