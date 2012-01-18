#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <inttypes.h>


#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>
#include <csprng/csprng.h>
#include <csprng/fips.h>


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_buffer
 *  Description:  
 * =====================================================================================
 */
static int
init_buffer ( rng_buf_type* data, unsigned int size )
{
  data->buf	= (unsigned char*) malloc ( size );
  if ( data->buf ==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  }
  errno = 0;
  if ( mlock(data->buf, size ) ) {
    //TODO - use getrlimit ?
    fprintf (stderr, "\nFunction init_buffer: cannot lock buffer to RAM. Size of buffer is %u Bytes; %s\n", size, strerror (errno) );
  }
  data->total_size = size;
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
 *         Name:  fill_buffer_using_HAVEGE
 *  Description:  
 * =====================================================================================
 */
static void
fill_buffer_using_HAVEGE ( rng_buf_type* data )
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
}		/* -----  end of function fill_buffer_using_HAVEGE  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buffer_using_csprng
 *         TODO - allow variable length of data from csprng_generate ??
 *  Description:  
 * =====================================================================================
 */
static int
fill_buffer_using_csprng (fips_state_type* fips_state)
{
  int return_status;
  rng_buf_type* data = &fips_state->raw_buf;

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  // 2. Fill buffer
  while ( data->valid_data_size + fips_state->max_number_of_csprng_generated_bytes <= data->total_size ) {
    return_status = csprng_generate ( &fips_state->csprng_state, data->buf_start + data->valid_data_size, fips_state->max_number_of_csprng_generated_bytes);
    if ( return_status ) return return_status;
    data->valid_data_size += fips_state->max_number_of_csprng_generated_bytes;
  }
  return 0;
}		/* -----  end of function fill_buffer_using_csprng  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_data_from_HAVEGE_buffer
 *  Description:  
 * =====================================================================================
 */
static const unsigned char*
get_data_from_HAVEGE_buffer ( rng_buf_type* data, int size )
{
  unsigned char* temp;
  if ( size > data->valid_data_size ) {
    fill_buffer_using_HAVEGE (data);
    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "\nBuffer does not support such big data sizes\n" );
      return (NULL);
    }
  }

  data->valid_data_size -= size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;

  return(temp);
}		/* -----  end of function get_data_from_HAVEGE_buffer  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_data_from_csprng_buffer
 *  Description:  
 * =====================================================================================
 */
static const unsigned char*
get_data_from_csprng_buffer ( fips_state_type* fips_state, int size)
{
  unsigned char* temp;
  rng_buf_type* data = &fips_state->raw_buf;
  if ( size > fips_state->raw_buf.valid_data_size ) {
    fill_buffer_using_csprng (fips_state);
    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "\nBuffer does not support such big data sizes\n" );
      return (NULL);
    }
  }

  data->valid_data_size -= size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;

  return(temp);
}		/* -----  end of function get_data_from_csprng_buffer  ----- */

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_init
 *  Description:  
 * =====================================================================================
 */
int
csprng_init ( csprng_state_type* csprng_state, const int use_df , const int use_additional_input, const int havege_debug_flags, const int havege_status_flag )
{
  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;
  char buf[2048];


  error = havege_init(0, 0, havege_debug_flags);
  if ( error ) {
    fprintf(stderr, "Error: havege_init has returned %d\n",error);
    return(error);
  }

  if ( havege_status_flag == 1 ) {
    havege_status(buf, 2048);
    fprintf(stderr,"================HAVEGE STATUS REPORT================\n");
    fprintf(stderr, "%s\n", buf);
    fprintf(stderr,"====================================================\n");
  }


  error = nist_ctr_initialize();
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_initialize has returned %d\n",error);
    return(error);
  }

  error = init_buffer( &csprng_state->rng_buf, 2 * HAVEGE_NDSIZECOLLECT );
  if ( error ) {
    fprintf(stderr, "Error: init_buffer has returned %d\n",error);
    return(error);
  }


  if ( use_df ) {
    csprng_state->use_df = 1;
    csprng_state->entropy_length = NIST_BLOCK_OUTLEN_BYTES;
    if ( use_additional_input ) {
      csprng_state->additional_input_length = NIST_BLOCK_OUTLEN_BYTES;
    } else {
      csprng_state->additional_input_length = 0;
    }
  } else {
    csprng_state->use_df = 0;
    csprng_state->entropy_length = 2 * NIST_BLOCK_OUTLEN_BYTES;
    if ( use_additional_input ) {
      csprng_state->additional_input_length = 2 * NIST_BLOCK_OUTLEN_BYTES;
    } else {
      csprng_state->additional_input_length = 0;
    }
  }


  entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
  if ( entropy == NULL) return(1);
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

  entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
  if ( entropy == NULL) return(1);
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
csprng_generate ( csprng_state_type* csprng_state, unsigned char* output_buffer, int output_size)
{
  // size is in Bytes. Ideally,  output_size is integer multiply of NIST_BLOCK_OUTLEN_BYTES
  
  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;

  if ( csprng_state->additional_input_length ) {
    //How often do we apply additioanal input?
    //For every NIST_BLOCK_OUTLEN_BYTES block or just once?
    additional_input = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->additional_input_length );
    if ( additional_input == NULL) return(1);
  
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
    entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
    if ( entropy == NULL) return(1);
    additional_input =  entropy + csprng_state->entropy_length;

    error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      return(error);
    }
  } else {
    entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length);
    if ( entropy == NULL) return(1);

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



int fips_approved_csprng_init(fips_state_type *fips_state, unsigned int max_number_of_csprng_blocks, unsigned int fips_continuos_test_seed,  const int use_df, const int use_additional_input, const int havege_debug_flags, const int havege_status_flag)
{
  int return_value=0;
  int error;

  error = csprng_init(&fips_state->csprng_state, use_df, use_additional_input, havege_debug_flags, havege_status_flag);
  if ( error ) {
    fprintf(stderr, "Error: csprng_init has returned %d\n", error);
    return(error);
  }

  fips_statistics_init(&fips_state->fips_statistics);

  fips_init( &fips_state->fips_ctx, fips_continuos_test_seed);

  fips_state->max_number_of_csprng_generated_bytes = max_number_of_csprng_blocks * NIST_BLOCK_OUTLEN_BYTES;
  
  error = init_buffer(&fips_state->raw_buf , fips_state->max_number_of_csprng_generated_bytes + FIPS_RNG_BUFFER_SIZE );
  if ( error ) {
    fprintf(stderr, "Error: init_buffer has returned %d\n",error);
    return(error);
  }

  error = init_buffer(&fips_state->out_buf , FIPS_RNG_BUFFER_SIZE );
  if ( error ) {
    fprintf(stderr, "Error: init_buffer has returned %d\n",error);
    return(error);
  }
  return return_value;
}

/* Would like a semi-open interval [min, max) */
int random_in_range (unsigned int min, unsigned int max)
{
  int base_random = random(); /* in [0, RAND_MAX] */
  if (RAND_MAX == base_random) return random_in_range(min, max);
  /* now guaranteed to be in [0, RAND_MAX) */
  int range       = max - min,
      remainder   = RAND_MAX % range,
      bucket      = RAND_MAX / range;
  /* There are range buckets, plus one smaller interval
     within remainder of RAND_MAX */
  if (base_random < RAND_MAX - remainder) {
    return min + base_random/bucket;
  } else {
    return random_in_range (min, max);
  }
}


int fips_run_rng_test_dummy (fips_ctx_t *ctx, const void *buf) {
  int a=random_in_range(0,1000);
  if (a>0) {
    return 0;
  } else {
    return 1;
  }
}

int fips_approved_csprng_generate (fips_state_type *fips_state, unsigned char *output_buffer, int output_size)
{
  fips_statistics_type* fips_statistics = &fips_state->fips_statistics;
  const unsigned char* raw_data;
  int fips_result;
  int bytes_to_put_into_buffer;
  int j;
  struct timespec cpu_s, cpu_e;
  struct timespec wall_s, wall_e;

//Do we have some data in the buffer??
  if ( fips_state->out_buf.valid_data_size > 0 ) {
    if ( fips_state->out_buf.valid_data_size >= output_size ) {
      memcpy(output_buffer, fips_state->out_buf.buf_start, output_size);
      fips_state->out_buf.buf_start += output_size;
      fips_state->out_buf.valid_data_size -= output_size;
      return 0;
    } else {
      memcpy(output_buffer, fips_state->out_buf.buf_start, fips_state->out_buf.valid_data_size);
      output_size -= fips_state->out_buf.valid_data_size;
      output_buffer += fips_state->out_buf.valid_data_size;
      fips_state->out_buf.buf_start = fips_state->out_buf.buf;
      fips_state->out_buf.valid_data_size = 0;
    }
  }

  while ( output_size > 0 ) {
    raw_data = get_data_from_csprng_buffer(fips_state, FIPS_RNG_BUFFER_SIZE);
    if ( raw_data == NULL) return(1);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_s);
    //fips_result = fips_run_rng_test_dummy(&fips_state->fips_ctx, raw_data);
    fips_result = fips_run_rng_test(&fips_state->fips_ctx, raw_data);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_e);   
    add_timing_difference_to_counter ( &fips_statistics->cpu_time, &cpu_s, &cpu_e );

   
    if (fips_result) {
      fips_statistics->bad_fips_blocks++;
      for (j = 0; j < N_FIPS_TESTS; j++) if (fips_result & fips_test_mask[j]) fips_statistics->fips_failures[j]++;
    } else {
      fips_statistics->good_fips_blocks++;

      //Check if we can copy data directly to output_buffer, without need to write to buffer fips_state->out_buf
      if ( output_size >= FIPS_RNG_BUFFER_SIZE) {
        memcpy(output_buffer, raw_data, FIPS_RNG_BUFFER_SIZE);
        output_size -= FIPS_RNG_BUFFER_SIZE;
        output_buffer += FIPS_RNG_BUFFER_SIZE;
      } else {
        memcpy(output_buffer, raw_data, output_size);
        //output_buffer += output_size;
        //output_size -= output_size;
        raw_data += output_size;
        bytes_to_put_into_buffer = FIPS_RNG_BUFFER_SIZE - output_size;
        assert(fips_state->out_buf.valid_data_size == 0);
        assert(fips_state->out_buf.total_size - fips_state->out_buf.valid_data_size >= bytes_to_put_into_buffer);
        memcpy(fips_state->out_buf.buf_start + fips_state->out_buf.valid_data_size, raw_data, bytes_to_put_into_buffer);
        fips_state->out_buf.valid_data_size += bytes_to_put_into_buffer;
  
      return 0;
      }
    }
  }
  return 0;
}

int fips_approved_csprng_destroy (fips_state_type *fips_state) 
{
  fips_statistics_type* fips_statistics = &fips_state->fips_statistics;
  int return_value=0;

  dump_fips_statistics( fips_statistics );
  return_value = csprng_destroy( &fips_state->csprng_state);
  destroy_buffer( &fips_state->out_buf);
  destroy_buffer( &fips_state->raw_buf);
  return return_value;

}
    
