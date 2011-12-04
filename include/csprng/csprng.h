#ifndef CSPRNG_H
#define CSPRNG_H

#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>


typedef struct {
  unsigned char* buf;       //Buffer to pass values from RNG to CTR_DRBG
  int total_size;           //Total size of buffer
  unsigned char* buf_start; //Start of valid data
  int valid_data_size;      //Size of valid data
} rng_buf_type;

typedef struct {
  int use_df;                   //Use derive function? 0=> False, 1=>True
  int entropy_length;           //Length of entropy in bytes
  int additional_input_length;  //Length of additional_input_length in bytes
  rng_buf_type rng_buf;         //Buffer between havege and CTR_DRBG
  NIST_CTR_DRBG ctr_drbg ;      //Internal state of CTR_DRBG
} csprng_state_type;


int csprng_destroy(csprng_state_type *csprng_state);
int csprng_generate(csprng_state_type *csprng_state,unsigned char *output_buffer, const int output_size);
int csprng_init(csprng_state_type *csprng_state, const int use_df, const int use_additional_input);

#endif

