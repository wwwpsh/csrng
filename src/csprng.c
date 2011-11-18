/* Simple main program 

   
src/csprng | dd of=/dev/null bs=4096 count=100000
src/csprng | pv > /dev/null
src/csprng | /home/jirka/C/64-bit/2011-Jan-20-dieharder/dieharder-3.31.0_BIN/bin/dieharder -g 200 -a

/home/jirka/C/64-bit/2011-Sep-16-HAVEGED/New_official_release/2011-Oct-20/haveged-1.3/src/haveged -n0 | dd of=/dev/null bs=4096 count=100000

*/


#include <stdlib.h>
#include <stdio.h>

#include "havege.h"
#include "nist_ctr_drbg.h"

static unsigned int buf_size=1024;

typedef struct {
  unsigned char* buf;       //Buffer to pass values from RNG to CTR_DRBG
  int total_size;           //Total size of buffer
  unsigned char* buf_start; //Start of valid data
  int valid_data_size;      //Size of valid data
} rng_buf_type;


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buffer
 *  Description:  
 * =====================================================================================
 */
void
fill_buffer ( rng_buf_type* data )
{
  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  // 2. Fill buffer
  while ( data->valid_data_size + HAVEGE_NDSIZECOLLECT <= data->total_size ) {
    memcpy(data->buf_start + data->valid_data_size, ndrand_full_buffer(), HAVEGE_NDSIZECOLLECT);
    data->valid_data_size += HAVEGE_NDSIZECOLLECT;
  }
}		/* -----  end of function fill_buffer  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_data_from_buffer
 *  Description:  
 * =====================================================================================
 */
const unsigned char*
get_data_from_buffer ( rng_buf_type* data, int size )
{
  unsigned char* temp;
  if ( size > data->valid_data_size ) {
    fill_buffer (data);
    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "\nBuffer does not support such big data sizes\n" );
      exit (EXIT_FAILURE);
    }
  }

  data->valid_data_size -= size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;

  return(temp);
}		/* -----  end of function get_data_from_buffer  ----- */


int main(int argc, char **argv) {
  //DATA_TYPE buf[buf_size];
  //DATA_TYPE *buf_pointer;
  unsigned int i;
  int error;
  rng_buf_type rng_buf;
  NIST_CTR_DRBG ctr_drbg ;   //Internal state of CTR_DRBG
  const unsigned char* entropy = NULL;
  unsigned char* nonce = NULL;
  int entropy_length = 0;
  int nonce_length = 0;
  unsigned char output_buffer[512*16];

  int use_df=0; //Use derive function? 0=>False


  rng_buf.buf	= (unsigned char*) malloc ( 2 * HAVEGE_NDSIZECOLLECT * sizeof(unsigned char) );
  if ( rng_buf.buf ==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    exit (EXIT_FAILURE);
  }
  rng_buf.total_size = 2 * HAVEGE_NDSIZECOLLECT;
  rng_buf.valid_data_size = 0;
  rng_buf.buf_start = rng_buf.buf;


  error = havege_init(0, 0, 15);
  if ( error ) {
    fprintf(stderr, "Error: havege_init has returned %d\n",error);
    exit(error);
  }

  error = nist_ctr_initialize();
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_initialize has returned %d\n",error);
    exit(error);
  }


  //char havege_status_buf[2048];
  //havege_status(havege_status_buf);
  //fprintf(stderr, "%s\n", havege_status_buf);


//   while(1) {
//     for(i=0;i<buf_size;i++)
//       buf[i] = ndrand();
//     fwrite (buf, 1, sizeof(DATA_TYPE) * buf_size, stdout);
//   }


  entropy_length = 32;
  nonce_length = 0 ;
  entropy = get_data_from_buffer( &rng_buf, entropy_length + nonce_length);
  nonce = NULL;

  dump_hex_byte_string(rng_buf.buf, entropy_length, "entropy_input: \t");
  dump_hex_byte_string(entropy, entropy_length, "entropy_input: \t");

  error = nist_ctr_drbg_instantiate(&ctr_drbg, entropy,  entropy_length, nonce, nonce_length, NULL, 0, use_df);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_instantiate has returned %d\n",error);
    exit(error);
  }

  entropy = get_data_from_buffer( &rng_buf, entropy_length);

  error = nist_ctr_drbg_reseed(&ctr_drbg, entropy, entropy_length, NULL, 0);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
    exit(error);
  }

  while(1) {
    error = nist_ctr_drbg_generate( &ctr_drbg, output_buffer, 512*16, NULL, 0);
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_generate has returned %d\n",error);
      exit(error);
    }
    fwrite (output_buffer, sizeof(unsigned char), 512*16, stdout);

    entropy = get_data_from_buffer( &rng_buf, entropy_length);

    error = nist_ctr_drbg_reseed(&ctr_drbg, entropy, entropy_length, NULL, 0);
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      exit(error);
    }
  }

//  while(1) {
//    fwrite (ndrand_full_buffer(), sizeof(DATA_TYPE), HAVEGE_NDSIZECOLLECT, stdout);
//  }

//   while(1) {
//     buf_pointer=ndrand_remaining_buffer(&i);
//     fwrite (buf_pointer, sizeof(DATA_TYPE), i, stdout);
//     ndrand();
//   }

  free (rng_buf.buf);
  rng_buf.buf	= NULL;
  return(EXIT_SUCCESS);
}
