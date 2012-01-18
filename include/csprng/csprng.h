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
  int use_df;                   //Use derive function? 0=> False, 1=>True
  int entropy_length;           //Length of entropy in bytes
  int additional_input_length;  //Length of additional_input_length in bytes
  rng_buf_type rng_buf;         //Buffer between havege and CTR_DRBG
  NIST_CTR_DRBG ctr_drbg ;      //Internal state of CTR_DRBG
} csprng_state_type;


typedef struct {
  unsigned int max_number_of_csprng_generated_bytes;  //This has influence on both csprng and also on size of the buffer. Recommended value is 512 * NIST_BLOCK_OUTLEN_BYTES
  csprng_state_type csprng_state;                     //State of csprng RNG
  rng_buf_type raw_buf;                               //Size of this buffer in Bytes is max_number_of_csprng_generated_bytes + FIPS_RNG_BUFFER_SIZE
  fips_statistics_type fips_statistics;               //Various FIPS statistics
  fips_ctx_t  fips_ctx;                               //FIPS context data 
  rng_buf_type out_buf;                               //Output buffer
} fips_state_type;



int csprng_destroy(csprng_state_type *csprng_state);
int csprng_generate(csprng_state_type *csprng_state,unsigned char *output_buffer, int output_size);
int csprng_init(csprng_state_type *csprng_state, const int use_df, const int use_additional_input, const int havege_debug_flags, const int havege_status_flag );


int fips_approved_csprng_destroy (fips_state_type *fips_state);
int fips_approved_csprng_generate (fips_state_type *fips_state, unsigned char *output_buffer, int output_size);
int fips_approved_csprng_init(fips_state_type *fips_state, unsigned int max_number_of_csprng_blocks, unsigned int fips_continuos_test_seed,  const int use_df, const int use_additional_input, const int havege_debug_flags, const int havege_status_flag);
#endif

