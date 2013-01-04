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

#ifndef HTTP_RNG_H
#define HTTP_RNG_H

#define RANDOM_ORG_ERR "You have used your quota of random bits for today"
#define HOTBITS_ERR "You have exceeded your 24-hour quota for HotBits."
#define RANDOMNUMBERS_INFO_BITS 13
#define RANDOMNUMBERS_INFO_MAX ( (1UL << RANDOMNUMBERS_INFO_BITS)  - 1UL)

//#define USERAGENT "csrng/1.1 (http://code.google.com/p/csrng/; Author: hladky.jiri@gmail.com)"
#define USERAGENT "Mozilla/5.0 (Windows; U; Windows NT 5.1; de; rv:1.9.0.1) Gecko/2008070208 Firefox/3.0.0"

#define MASK_HOTBITS 1
#define MASK_RANDOM_ORG 2
#define MASK_RANDOMNUMBERS_INFO 4
#define MASK_QRBG 8


#include <csprng/fips.h>

typedef enum {HOTBITS_RNG, RANDOM_ORG_RNG, RANDOMNUMBERS_INFO_RNG, QRBG_RNG, HTTP_COUNT } http_random_source_t;
extern const char* const http_random_source_names[HTTP_COUNT];
extern const char* const http_random_source_server[HTTP_COUNT];
extern const char* const http_random_source_port[HTTP_COUNT];

typedef enum { STATE_NOT_STARTED, STATE_RUNNING, STATE_WAITING_FOR_BUFFER_TO_BE_EMPTY, 
               STATE_SLEEPING, STATE_FINISHED, STATE_COUNT } http_random_thread_state_t;

typedef struct {
  char source;                               //bitmask describing which sources to use. All sources ( MASK_HOTBITS | MASK_RANDOM_ORG | MASK_RANDOMNUMBERS_INFO | MASK_QRBG )
  uint8_t* buf;                              //buffer to exchange data between multiple producers and one consumer
  uint8_t* buf_start;                        //pointer to start of the valid data
  uint64_t data_added[HTTP_COUNT];           //Total bytes added
  uint64_t fips_tests_executed[HTTP_COUNT];  //Number of FIPS tests executed by given thread. Please not that FIPS validation is triggered
                                             //whenever buffer has enough bytes. So some bytes may come from another server
  uint64_t fips_fails[HTTP_COUNT];           //FIPS failures.  Please not that FIPS validation is triggered
                                             //whenever buffer has enough bytes. So some bytes may come from another server
  size_t size;                               //total size of the buffer
  size_t valid_data;                         //valid data size
  size_t fips_valided;                       //size of FIPS validaded data
  size_t fips_fails_in_row;                  //FIPS fails in row
  size_t max_fips_fails_in_row;              //max FIPS fails in row
  fips_ctx_t fips_ctx;                       //FIPS validation of the data
  char verbosity;                            //verbosity level
} http_random_state_t;

http_random_state_t* http_random_init(char source, size_t size, char verbosity, const char* QRBG_RNG_user_input, const char* QRBG_RNG_passwd_input);
unsigned int http_random_generate(http_random_state_t* state, uint8_t* output, size_t size, unsigned int max_timeout);
unsigned int http_random_destroy(http_random_state_t* state);
unsigned int http_random_status(http_random_state_t* state, char print);
#endif
