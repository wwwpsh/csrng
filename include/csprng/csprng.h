/*
Copyright (C) 2011, 2012 Jirka Hladky

This file is part of CSPRNG.

CSPRNG is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CSPRNG is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with CSPRNG.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef CSPRNG_H
#define CSPRNG_H

#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>
#include <csprng/fips.h>



typedef struct {
  unsigned char* buf;       //Buffer to pass values from RNG to CTR_DRBG
  int total_size;           //Total size of buffer
  unsigned char* buf_start; //Start of valid data
  int valid_data_size;      //Size of valid data
} rng_buf_type;

typedef struct {
  int use_df;                   //Use derivation function? 0=> False, 1=>True
  int entropy_length;           //Length of entropy in bytes
  int additional_input_length;  //Length of additional_input_length in bytes
  rng_buf_type rng_buf;         //Buffer between havege and CTR_DRBG
  NIST_CTR_DRBG ctr_drbg ;      //Internal state of CTR_DRBG
} csprng_state_type;

typedef struct {
  int use_df;                         //Use deriavation function? 0=> False, 1=>True
  int use_additional_input;           //Use additional input?     0=> False, 1=>True
  int havege_debug_flags;             //HAVEGE debug flags
  int havege_status_flag;             //HAVEGE status flag
  int havege_instruction_cache_size;  //HAVEGE - CPU instruction cache size in kB
  int havege_data_cache_size;         //HAVEGE - CPU data cache size in kB
} mode_of_operation_type;

typedef struct {
  unsigned int max_number_of_csprng_generated_bytes;  //This has influence on both csprng and also on size of the buffer. Recommended value is 512 * NIST_BLOCK_OUTLEN_BYTES
  unsigned int max_number_of_csprng_blocks;           // max_number_of_csprng_generated_bytes = INTEGER * max_number_of_csprng_blocks
  int random_length_of_csprng_generated_bytes;        // 0 => disabled, 1 => enabled
  csprng_state_type csprng_state;                     //State of csprng RNG
  rng_buf_type raw_buf;                               //Size of this buffer in Bytes is 
                                                      //max_number_of_csprng_generated_bytes + max_bytes_to_get_from_raw_buf
  rng_buf_type out_buf;                               //Output buffer
  int perform_fips_test;                              // 0=> FIPS tests are disabled. 1=>FIPS tests are enabled
  int max_bytes_to_get_from_raw_buf;                  //Safe value for get_data_from_csprng_buffer. Size of raw_buf in bytes is
                                                      // max_number_of_csprng_generated_bytes + max_bytes_to_get_from_raw_buf
  fips_ctx_t  fips_ctx;                               //FIPS context data 
} fips_state_type;



int csprng_destroy(csprng_state_type *csprng_state);
int csprng_generate(csprng_state_type *csprng_state,unsigned char *output_buffer, int output_size);
int csprng_init(csprng_state_type *csprng_state, const mode_of_operation_type* mode_of_operation);


int fips_approved_csprng_destroy (fips_state_type *fips_state);
int fips_approved_csprng_generate (fips_state_type *fips_state, unsigned char *output_buffer, int output_size);
int fips_approved_csprng_init(fips_state_type *fips_state, int perform_fips_test,
    unsigned int max_number_of_csprng_blocks, int random_length_of_csprng_generated_bytes, int track_fips_CPU_time,
    const mode_of_operation_type* mode_of_operation);
#endif

