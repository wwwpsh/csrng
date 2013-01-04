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

#ifndef CSPRNG_H
#define CSPRNG_H

#include <inttypes.h>
#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>
#include <csprng/memt19937ar-JH.h>
#include <csprng/sha1_rng.h>
#include <csprng/http_rng.h>
#include <csprng/fips.h>

//How long wait for HTTP source?
#define HTTP_TIMEOUT_IN_SECONDS 45

typedef enum {NONE, HAVEGE, SHA1_RNG, MT_RNG, HTTP_RNG, STDIN, EXTERNAL, SOURCES_COUNT} rand_source_type;
// HAVEGE = HAVEGE RNG
// SHA1_RNG = SHA-1 GENERATOR
// MT_RNG = Mersenne Twister
// HTTP_RNG = Internet sources. Currently following servers are supported "www.fourmilab.ch", "www.random.org", "www.randomnumbers.info"
// STDIN = standard input
// EXTERNAL = FILE (PIPE or REGULAR FILE)
// SOURCES_COUNT => STOP POINT
extern const char* const source_names[SOURCES_COUNT];


typedef union {
  memt_type* memt;           //Describes Mersenne Twister state
  SHA1_state* sha;           //Describes SHA-1 state
  http_random_state_t* http; //Describes HTTP state
} rng_state_type; 

typedef struct {
  unsigned char* buf;               //Buffer to pass values from RNG to CTR_DRBG
  unsigned int total_size;          //Total size of buffer
  unsigned char* buf_start;         //Start of valid data
  unsigned int valid_data_size;     //Size of valid data
  char* filename;                   //FILENAME connected with fd
  FILE* fd;                         //Read data from fd. Use NULL if not used
  int eof;                          //EOF detected?
  char locked;                      //Is memory locked? 0=> False, 1=>True
  rand_source_type source;          //SOURCE
  rng_state_type rng_state;         //STATE OF RNG
  char* buffer_name;                //NAME OF THE BUFFER for debugging purposes
  uint64_t bytes_in;                //Total of bytes received
  uint64_t bytes_out;               //Total of bytes sent out 
} rng_buf_type;

typedef struct {
  int use_df;                                         //Use deriavation function? 0=> False, 1=>True
  int havege_debug_flags;                             //HAVEGE debug flags
  int havege_status_flag;                             //HAVEGE status flag
  int havege_instruction_cache_size;                  //HAVEGE - CPU instruction cache size in kB
  int havege_data_cache_size;                         //HAVEGE - CPU data cache size in kB
  int http_random_verbosity;                          //HTTP_RNG - verbosity level
  char *filename_for_entropy;                         //FILENAME associated with file_for_entropy_buf
  char *filename_for_additional;                      //FILENAME associated with file_for_additional_buf
  int file_read_size;                                 //Read size for FILE
  rand_source_type entropy_source;                    //Source of entropy - HAVEGE, MT, EXTERNAL ?
  rand_source_type add_input_source;                  //Source of additional input - HAVEGE, MT, EXTERNAL ?
  unsigned int max_number_of_csprng_generated_bytes;  //Bytes generated without reseed. Typical value 512 * NIST_BLOCK_OUTLEN_BYTES. Note that CSPRNG can generate 
                                                      //maximum NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST bytes per one generate call
                                                      //if ( max_number_of_csprng_generated_bytes > NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST) => multiple generate calls are needed
  unsigned int max_number_of_csprng_blocks;           // max_number_of_csprng_generated_bytes = INTEGER * max_number_of_csprng_blocks
  int random_length_of_csprng_generated_bytes;        // 0 => disabled, 1 => enabled
} mode_of_operation_type;

typedef struct {
  int entropy_length;                                 //Length of entropy in bytes
  uint64_t entropy_tot;                               //Total entropy bytes consumed for reseed process
  int additional_input_length_generate;               //Length of additional_input_length in bytes for generate function
  uint64_t additional_input_generate_tot;             //Total additional_input bytes consumed for generate process
  int additional_input_length_reseed;                 //Length of additional_input_length in bytes for reseed function
  uint64_t additional_input_reseed_tot;               //Total additional_input bytes consumed for reseed process
  int are_files_same;                                 //Point files file_for_entropy_buf and file_for_additional_buf to the same file? 
  FILE *file_for_entropy_buf;                         //Read data from FILE instead of RNG algorithm for entropy_buf
  FILE *file_for_additional_buf;                      //Read data from FILE instead of RNG algorithm for add_input_buf
  rng_buf_type* entropy_buf;                          //Entropy buffer between havege/FILE and CTR_DRBG
  rng_buf_type* add_input_buf;                        //Additional input buffer between havege/FILE and CTR_DRBG
  rng_buf_type* random_length_buf;                    //Buffer of random numbers to derive random_length_of_csprng_generated_bytes
  NIST_CTR_DRBG* ctr_drbg ;                           //Internal state of CTR_DRBG
  int HAVEGE_initialized;                             //Was HAVEGE initialized?
  SHA1_state* sha;                                    //internal state of SHA-1 RNG
  memt_type* memt;                                    //Internal state of Mersenne Twister RNG
  http_random_state_t* http;                          //Internal state of the HTTP (internet based) RNG
  mode_of_operation_type mode;                        //Mode of operation
} csprng_state_type;

typedef struct {
  csprng_state_type* csprng_state;                    //State of csprng RNG
  rng_buf_type* raw_buf;                              //Size of this buffer in Bytes is 
                                                      //max_number_of_csprng_generated_bytes + max_bytes_to_get_from_raw_buf
  rng_buf_type* out_buf;                              //Output buffer
  int perform_fips_test;                              // 0=> FIPS tests are disabled. 1=>FIPS tests are enabled
  int max_bytes_to_get_from_raw_buf;                  //Safe value for get_data_from_csprng_buffer. Size of raw_buf in bytes is
                                                      // max_number_of_csprng_generated_bytes + max_bytes_to_get_from_raw_buf
  fips_ctx_t  fips_ctx;                               //FIPS context data 
} fips_state_type;



int csprng_destroy(csprng_state_type *csprng_state);
int csprng_generate(csprng_state_type *csprng_state,unsigned char *output_buffer, unsigned int output_size, uint8_t reseed);
csprng_state_type* csprng_initialize( const mode_of_operation_type* mode_of_operation);
int csprng_instantiate ( csprng_state_type* csprng_state );
void csprng_estimate_bytes_needed ( csprng_state_type* csprng_state, char unlimited, uint64_t size, uint64_t output_buffer_size,
    char verbose, long double http_reasonable_length, long double http_rng_rate, long double target_rate );

int fips_approved_csprng_destroy (fips_state_type *fips_state);
int fips_approved_csprng_generate (fips_state_type *fips_state, unsigned char *output_buffer, unsigned int output_size);
int fips_approved_csprng_statistics (fips_state_type *fips_state) ;
fips_state_type* fips_approved_csprng_initialize(int perform_fips_test, int track_fips_CPU_time, const mode_of_operation_type* mode_of_operation);
int fips_approved_csprng_instantiate( fips_state_type* fips_state);
#endif

