#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>
#include <csprng/csprng.h>


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_buffer
 *  Description:  
 * =====================================================================================
 */
static int
init_buffer ( rng_buf_type* data )
{
  data->buf	= (unsigned char*) malloc ( 2 * HAVEGE_NDSIZECOLLECT * sizeof(unsigned char) );
  if ( data->buf ==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  }
  data->total_size = 2 * HAVEGE_NDSIZECOLLECT;
  data->valid_data_size = 0;
  data->buf_start = data->buf;
  return 0;
}		/* -----  end of static function init_buffer  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  destroy_buffer
 *  Description:  
 * =====================================================================================
 */
static void
destroy_buffer ( rng_buf_type* data )
{
  free (data->buf);
  data->buf	= NULL;
  data->buf_start = NULL;
  data->total_size = 0;
  data->valid_data_size = 0;
}		/* -----  end of static function destroy_buffer  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buffer
 *  Description:  
 * =====================================================================================
 */
static void
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
static const unsigned char*
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


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_init
 *  Description:  
 * =====================================================================================
 */
int
csprng_init ( csprng_state_type* csprng_state, const int use_df , const int use_additional_input )
{
  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;

  error = havege_init(0, 0, 15);
  if ( error ) {
    fprintf(stderr, "Error: havege_init has returned %d\n",error);
    return(error);
  }

  error = nist_ctr_initialize();
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_initialize has returned %d\n",error);
    return(error);
  }

  error = init_buffer( &csprng_state->rng_buf );
  if ( error ) {
    fprintf(stderr, "Error: init_buffer has returned %d\n",error);
    return(error);
  }


  if ( use_df ) {
    csprng_state->use_df = 1;
    csprng_state->entropy_length = 16;
    if ( use_additional_input ) {
      csprng_state->additional_input_length = 16;
    } else {
      csprng_state->additional_input_length = 0;
    }
  } else {
    csprng_state->use_df = 1;
    csprng_state->entropy_length = 32;
    if ( use_additional_input ) {
      csprng_state->additional_input_length = 32;
    } else {
      csprng_state->additional_input_length = 0;
    }
  }


  entropy = get_data_from_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
  if ( use_additional_input ) {
    additional_input =  entropy + csprng_state->entropy_length;
  } else {
    additional_input = NULL;
  }


//  dump_hex_byte_string(&csprng_state->rng_buf.buf, entropy_length, "entropy_input: \t");
//  dump_hex_byte_string(entropy, entropy_length, "entropy_input: \t");

  error = nist_ctr_drbg_instantiate(&csprng_state->ctr_drbg, entropy,  csprng_state->entropy_length, NULL, 0, additional_input , csprng_state->additional_input_length, use_df);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_instantiate has returned %d\n",error);
    return(error);
  }

  entropy = get_data_from_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
  if ( use_additional_input ) {
    additional_input =  entropy + csprng_state->entropy_length;
  } 

  error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
    return( error );
  }

  return (0);

}		/* -----  end of static function csprng_init  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_generate
 *  Description:  
 * =====================================================================================
 */
int
csprng_generate ( csprng_state_type* csprng_state, unsigned char* output_buffer, const int output_size)
{
  // size is in Bytes. Note that we are generating NIST_BLOCK_OUTLEN_BYTES per one request
  assert( output_size % NIST_BLOCK_OUTLEN_BYTES == 0);

  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;

  if ( csprng_state->additional_input_length ) {
    //How often do we apply additioanal input?
    //For every NIST_BLOCK_OUTLEN_BYTES block or just once?
    additional_input = get_data_from_buffer( &csprng_state->rng_buf, csprng_state->additional_input_length );
  
    error = nist_ctr_drbg_generate( &csprng_state->ctr_drbg, output_buffer, output_size, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_generate has returned %d\n",error);
      return(error);
    }

  } else {

    error = nist_ctr_drbg_generate( &csprng_state->ctr_drbg, output_buffer, output_size, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_generate has returned %d\n",error);
      return(error);
    }
  }

  //fwrite (output_buffer, sizeof(unsigned char), 512*16, stdout);

  if ( csprng_state->additional_input_length ) {
    entropy = get_data_from_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
    additional_input =  entropy + csprng_state->entropy_length;

    error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      return(error);
    }
  } else {
    entropy = get_data_from_buffer( &csprng_state->rng_buf, csprng_state->entropy_length);

    error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      return(error);
    }
  }


  return 0;
}		/* -----  end of function csprng_generate  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_destroy
 *  Description:  
 * =====================================================================================
 */
int
csprng_destroy ( csprng_state_type* csprng_state )
{
  int return_value=0;
  int error;

  destroy_buffer( &csprng_state->rng_buf );

  error = nist_ctr_drbg_destroy(&csprng_state->ctr_drbg);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_destroy has returned %d\n",error);
    return_value = error;
  }


  return return_value;
}		/* -----  end of function csprng_destroy  ----- */

