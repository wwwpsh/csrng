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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <inttypes.h>

#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>
#include <csprng/csprng.h>
#include <csprng/fips.h>

//{{{ init_buffer
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_buffer
 *  Description:  Allocate memory for rng_buf_type and lock it to RAM if possible
 * =====================================================================================
 */
static int
init_buffer ( rng_buf_type* data, unsigned int size )
{
  //fprintf ( stderr, "\nTrying to allocate buffer of size %u Bytes\n", size);

  data->buf	= (unsigned char*) malloc ( size );
  if ( data->buf ==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  }
  errno = 0;
  if ( size < 16384 ) {
    //TODO - use getrlimit ?
    if ( mlock(data->buf, size ) ) {
      fprintf (stderr, "\nWarning: Function init_buffer: cannot lock buffer to RAM (preventing that memory from being paged to the swap area)\n"
          "Size of buffer is %u Bytes; %s\n", size, strerror (errno) );
    }
  }
  data->total_size = size;
  data->valid_data_size = 0;
  data->buf_start = data->buf;
  return 0;
}		/* -----  end of static function init_buffer  ----- */
//}}}

//{{{ destroy_buffer
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  destroy_buffer
 *  Description:  Free buffer of type rng_buf_type
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
//}}}

//{{{ fill_buffer_using_HAVEGE
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buffer_using_HAVEGE
 *  Description:  Fill rng_buf_type using HAVEGE
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
//}}}

//{{{ get_data_from_HAVEGE_buffer
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_data_from_HAVEGE_buffer
 *  Description:  Return pointer to data in HAVEGE buffer
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
//}}}

//{{{ fill_buffer_using_csprng
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buffer_using_csprng
 *  Description:  This will fill buffer using CSPRNG algorithm
 * =====================================================================================
 */
static int
fill_buffer_using_csprng (fips_state_type* fips_state)
{
  int generated_bytes;
  int bytes_to_generate, csprng_blocks_to_generate;
  rng_buf_type* data = &fips_state->raw_buf;
  rng_buf_type* havege_data;
  const uint32_t* havege_random;
  const unsigned char* result;
  int bucket = UINT32_MAX / fips_state->max_number_of_csprng_blocks;

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  // How many bytes are we going to generate? Either fips_state->max_number_of_csprng_generated_bytes or random number of bytes
  if ( fips_state->random_length_of_csprng_generated_bytes == 0 ) {
    bytes_to_generate = fips_state->max_number_of_csprng_generated_bytes;
  } else {
    havege_data = &fips_state->csprng_state.rng_buf;
    result = get_data_from_HAVEGE_buffer ( havege_data, 4);
    // We will use uniform distribution <1, fips_state->max_number_of_csprng_blocks>. 
    // Last value fips_state->max_number_of_csprng_blocks will have slightly higher frequency
    if ( result == NULL ) return 1;
    havege_random = (uint32_t*) (result) ;
    csprng_blocks_to_generate =  1 + *havege_random / bucket ;
    if ( csprng_blocks_to_generate > fips_state->max_number_of_csprng_blocks ) csprng_blocks_to_generate = fips_state->max_number_of_csprng_blocks;
    //fprintf(stderr,"%1" PRId32 "\n", csprng_blocks_to_generate);
    bytes_to_generate = csprng_blocks_to_generate * NIST_BLOCK_OUTLEN_BYTES;
    
  }

  // 2. Fill buffer
  while ( data->valid_data_size + bytes_to_generate <= data->total_size ) {
    generated_bytes = csprng_generate ( &fips_state->csprng_state, data->buf_start + data->valid_data_size, bytes_to_generate);
    if ( generated_bytes != bytes_to_generate ) return 1;
    data->valid_data_size += bytes_to_generate;

    if ( fips_state->random_length_of_csprng_generated_bytes == 1 ) {
      havege_data = &fips_state->csprng_state.rng_buf;
      result = get_data_from_HAVEGE_buffer ( havege_data, 4);
      if ( result == NULL ) return 1;
      havege_random = (uint32_t*) (result) ;
      csprng_blocks_to_generate =  1 + *havege_random / bucket ;
      if ( csprng_blocks_to_generate > fips_state->max_number_of_csprng_blocks ) csprng_blocks_to_generate = fips_state->max_number_of_csprng_blocks;
      //fprintf(stderr,"%1" PRId32 "\n", csprng_blocks_to_generate);
      bytes_to_generate = csprng_blocks_to_generate * NIST_BLOCK_OUTLEN_BYTES;
    }
  }
  return 0;
}		/* -----  end of function fill_buffer_using_csprng  ----- */
//}}}

//{{{ get_data_from_csprng_buffer
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_data_from_csprng_buffer
 *  Description:  Return pointer to data from the CSPRNG buffer. 
 * =====================================================================================
 */
static const unsigned char*
get_data_from_csprng_buffer ( fips_state_type* fips_state, int size)
{
  unsigned char* temp;
  rng_buf_type* data = &fips_state->raw_buf;
  if ( size > data->valid_data_size ) {
    fill_buffer_using_csprng (fips_state);
    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "ERROR: Failed to get requested bytes.\n" );
      fprintf ( stderr, "       Bytes requested %d, bytes available %d.\n", size, data->valid_data_size );
      return (NULL);
    }
  }

  data->valid_data_size -= size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;

  return(temp);
}		/* -----  end of function get_data_from_csprng_buffer  ----- */
//}}}

//{{{ csprng_init
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_init
 *  Description:  Init csprng
 * =====================================================================================
 */
int
csprng_init ( csprng_state_type* csprng_state, const mode_of_operation_type* mode_of_operation)
{
  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;
  char buf[2048];


  error = havege_init(mode_of_operation->havege_instruction_cache_size, mode_of_operation->havege_data_cache_size, mode_of_operation->havege_debug_flags); //TODO - support dcache size and icache size
  if ( error ) {
    fprintf(stderr, "Error: havege_init has returned %d\n",error);
    return(error);
  }

  if ( mode_of_operation->havege_status_flag == 1 ) {
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


  if ( mode_of_operation->use_df == 1) {
    csprng_state->use_df = 1;
    csprng_state->entropy_length = NIST_BLOCK_OUTLEN_BYTES;
    if ( mode_of_operation->use_additional_input ) {
      csprng_state->additional_input_length = NIST_BLOCK_OUTLEN_BYTES;
    } else {
      csprng_state->additional_input_length = 0;
    }
  } else {
    csprng_state->use_df = 0;
    csprng_state->entropy_length = NIST_BLOCK_SEEDLEN_BYTES;
    if ( mode_of_operation->use_additional_input ) {
      csprng_state->additional_input_length = NIST_BLOCK_SEEDLEN_BYTES;
    } else {
      csprng_state->additional_input_length = 0;
    }
  }


  entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
  if ( entropy == NULL) return(1);
//  dump_hex_byte_string(entropy, csprng_state->entropy_length, "Init:    \tentropy_input:     \t");
  if ( mode_of_operation->use_additional_input ) {
    additional_input =  entropy + csprng_state->entropy_length;
//    dump_hex_byte_string(additional_input, csprng_state->additional_input_length, "Init:    \tadditional_input: \t");
  } else {
    additional_input = NULL;
  }


//  dump_hex_byte_string(&csprng_state->rng_buf.buf, entropy_length, "entropy_input: \t");
//  dump_hex_byte_string(entropy, entropy_length, "entropy_input: \t");

  error = nist_ctr_drbg_instantiate(&csprng_state->ctr_drbg, entropy,  csprng_state->entropy_length, NULL, 0, 
      additional_input , csprng_state->additional_input_length, mode_of_operation->use_df);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_instantiate has returned %d\n",error);
    return(error);
  }

  entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
  if ( entropy == NULL) return(1);
//  dump_hex_byte_string(entropy, csprng_state->entropy_length, "Init, res: \tentropy_input:     \t");
  if ( mode_of_operation->use_additional_input ) {
    additional_input =  entropy + csprng_state->entropy_length;
    //dump_hex_byte_string(additional_input, csprng_state->additional_input_length, "Init, res: \tadditional_input: \t");
  } 

  error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
    return( error );
  }

  return (0);

}		/* -----  end of static function csprng_init  ----- */
//}}}

//{{{ csprng_generate
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_generate
 *  Description:  Generate data using csprng
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
    additional_input = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->additional_input_length );
    if ( additional_input == NULL) return(1);
    //dump_hex_byte_string(additional_input, csprng_state->additional_input_length, "Generate: \tadditional_input: \t");
  
    error = nist_ctr_drbg_generate( &csprng_state->ctr_drbg, output_buffer, output_size, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_generate has returned %d\n",error);
      return(0);
    }

  } else {

    error = nist_ctr_drbg_generate( &csprng_state->ctr_drbg, output_buffer, output_size, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_generate has returned %d\n",error);
      return(0);
    }
  }

  //fwrite (output_buffer, sizeof(unsigned char), 512*16, stdout);

  if ( csprng_state->additional_input_length ) {
    entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length + csprng_state->additional_input_length);
    if ( entropy == NULL) return(0);
    //dump_hex_byte_string(entropy, csprng_state->entropy_length, "Reseed: \tentropy_input:     \t");
    additional_input =  entropy + csprng_state->entropy_length;
    //dump_hex_byte_string(additional_input, csprng_state->additional_input_length, "Reseed: \tadditional_input: \t");

    error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      return(0);
    }
  } else {
    entropy = get_data_from_HAVEGE_buffer( &csprng_state->rng_buf, csprng_state->entropy_length);
    if ( entropy == NULL) return(0);
    //dump_hex_byte_string(entropy, csprng_state->entropy_length, "Reseed: \tentropy_input:     \t");

    error = nist_ctr_drbg_reseed(&csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length );
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      return(0);
    }
  }


  return output_size;
}		/* -----  end of function csprng_generate  ----- */
//}}}

//{{{ csprng_destroy
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_destroy
 *  Description:  Destroy rng_buf which holds csprng data
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
//}}}

//{{{ fips_approved_csprng_init
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fips_approved_csprng_init
 *  Description:  Init buffer between CSPRNG output and FIPS input
 * =====================================================================================
 */
int fips_approved_csprng_init(fips_state_type *fips_state, int perform_fips_test,
    unsigned int max_number_of_csprng_blocks, int random_length_of_csprng_generated_bytes, int track_fips_CPU_time,
    const mode_of_operation_type* mode_of_operation)
{
  int return_value=0;
  int error;
  const unsigned char* result;
  unsigned int fips_continuos_test_seed;

  error = csprng_init(&fips_state->csprng_state, mode_of_operation);
  if ( error ) {
    fprintf(stderr, "Error: csprng_init has returned %d\n", error);
    return(error);
  }

  fips_state->max_number_of_csprng_blocks = max_number_of_csprng_blocks;
  fips_state->max_number_of_csprng_generated_bytes = max_number_of_csprng_blocks * NIST_BLOCK_OUTLEN_BYTES;

  if ( random_length_of_csprng_generated_bytes ) {
    fips_state->random_length_of_csprng_generated_bytes = 1;
  } else {
    fips_state->random_length_of_csprng_generated_bytes = 0;
  }

  if ( perform_fips_test ) {
    fips_state->perform_fips_test = 1;
    result = get_data_from_HAVEGE_buffer ( &fips_state->csprng_state.rng_buf, sizeof(fips_continuos_test_seed));
    if ( result == NULL ) {
      fprintf(stderr, "Error:get_data_from_HAVEGE_buffer has returned NULL pointer\n");
      return 1;
    }
    fips_continuos_test_seed = (unsigned int) (*result);
    fips_state->max_bytes_to_get_from_raw_buf = FIPS_RNG_BUFFER_SIZE;
  } else {
    fips_state->perform_fips_test = 0;
    fips_continuos_test_seed = 0;
    fips_state->max_bytes_to_get_from_raw_buf = fips_state->max_number_of_csprng_generated_bytes;
  }


  fips_init( &fips_state->fips_ctx, fips_continuos_test_seed, track_fips_CPU_time);


  
  error = init_buffer(&fips_state->raw_buf , fips_state->max_number_of_csprng_generated_bytes +  fips_state->max_bytes_to_get_from_raw_buf);
  if ( error ) {
    fprintf(stderr, "Error: init_buffer has returned %d\n",error);
    return(error);
  }

  error = init_buffer(&fips_state->out_buf , fips_state->max_bytes_to_get_from_raw_buf );
  if ( error ) {
    fprintf(stderr, "Error: init_buffer has returned %d\n",error);
    return(error);
  }
  return return_value;
} /* -----  end of function fips_approved_csprng_init  ----- */
//}}}

//{{{ Functions for testing purposes 
#if 0
//{{{ random_in_range
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  random_in_range
 *  Description:  Return random integer in interval [min, max)
 * =====================================================================================
 */

/* Would like a semi-open interval [min, max) */
static int random_in_range (unsigned int min, unsigned int max)
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
//}}}

//{{{ fips_run_rng_test_dummy
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fips_run_rng_test_dummy
 *  Description:  Function to "emulate" fips test. Only for testing purposes.
 * =====================================================================================
 */
static int fips_run_rng_test_dummy (fips_ctx_t *ctx, const void *buf) {
  int a=random_in_range(0,1000);
  if (a>0) {
    return 0;
  } else {
    return 0;
  }
}
//}}}

//{{{ fill_buffer_using_stdin
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buffer_using_stdin
 *  Description:  This will fill buffer using STDIN. Designed for testing purposes only.
 * =====================================================================================
 */
static int
fill_buffer_using_stdin (fips_state_type* fips_state)
{
  rng_buf_type* data = &fips_state->raw_buf;
  int blocks_read;
  static double total=0.0;

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  // 2. Fill buffer
  while ( data->valid_data_size + fips_state->max_number_of_csprng_generated_bytes <= data->total_size ) {
    blocks_read = fread ( data->buf_start + data->valid_data_size, 1, fips_state->max_number_of_csprng_generated_bytes, stdin);
    data->valid_data_size += blocks_read;
    total += blocks_read;
    if ( blocks_read < fips_state->max_number_of_csprng_generated_bytes ) {
      if (feof(stdin)) {
        fprintf(stderr,"# stdin_input_raw(): EOF detected\n");
      } else {
        fprintf(stderr,"# stdin_input_raw(): Error: %s\n", strerror(errno));
      }
      fprintf(stderr, "Total bytes read %.14g\n", total);
      return (0);
    }
  }
  return 0;
}		/* -----  end of function fill_buffer_using_stdin  ----- */
//}}}

//{{{ get_data_from_stdin_buffer
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_data_from_stdin_buffer
 *  Description:  This will fill buffer with data from STDIN. Used for testing purposes only.
 * =====================================================================================
 */
static const unsigned char*
get_data_from_stdin_buffer ( fips_state_type* fips_state, int size)
{
  unsigned char* temp;
  rng_buf_type* data = &fips_state->raw_buf;
  if ( size > data->valid_data_size ) {
    fill_buffer_using_stdin (fips_state);
    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "ERROR: Failed to get requested bytes.\n" );
      fprintf ( stderr, "       Bytes requested %d, bytes available %d.\n", size, data->valid_data_size );
      return (NULL);
    }
  }

  data->valid_data_size -= size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;

  return(temp);
}		/* -----  end of function get_data_from_stdin_buffer  ----- */
//}}}
#endif
//}}}

//{{{ fips_approved_csprng_generate
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fips_approved_csprng_generate
 *  Description:  This will copy FIPS approved data to the output buffer
 * =====================================================================================
 */
int fips_approved_csprng_generate (fips_state_type *fips_state, unsigned char *output_buffer, int output_size)
{
  const unsigned char* raw_data;
  int fips_result=0;
  int bytes_to_put_into_buffer;
  int bytes_written=0;
  int remaining_bytes;
  int requested_bytes;

//Do we have some data in the buffer??
  if ( fips_state->out_buf.valid_data_size > 0 ) {
    if ( fips_state->out_buf.valid_data_size < output_size ) {
      memcpy(output_buffer, fips_state->out_buf.buf_start, fips_state->out_buf.valid_data_size);
      bytes_written += fips_state->out_buf.valid_data_size;
      output_buffer += fips_state->out_buf.valid_data_size;
      fips_state->out_buf.buf_start = fips_state->out_buf.buf;
      fips_state->out_buf.valid_data_size = 0;
    } else if ( fips_state->out_buf.valid_data_size == output_size) {
      memcpy(output_buffer, fips_state->out_buf.buf_start, output_size);
      fips_state->out_buf.buf_start = fips_state->out_buf.buf;
      fips_state->out_buf.valid_data_size = 0;
      return output_size;
    } else {
      memcpy(output_buffer, fips_state->out_buf.buf_start, output_size);
      fips_state->out_buf.buf_start += output_size;
      fips_state->out_buf.valid_data_size -= output_size;
      return output_size;
    }
  }

  remaining_bytes = output_size - bytes_written;
  while ( bytes_written < output_size ) {

    if ( fips_state->perform_fips_test ) {
      requested_bytes = FIPS_RNG_BUFFER_SIZE;
      raw_data = get_data_from_csprng_buffer(fips_state, requested_bytes);
      //raw_data = get_data_from_stdin_buffer(fips_state, requested_bytes);
      if ( raw_data == NULL) return(bytes_written);
      //fips_result = fips_run_rng_test_dummy(&fips_state->fips_ctx, raw_data);
      fips_result = fips_run_rng_test(&fips_state->fips_ctx, raw_data);
    } else {
      //We will eliminate need to put any data to out_buf
      if ( remaining_bytes > fips_state->max_bytes_to_get_from_raw_buf) {
        requested_bytes = fips_state->max_bytes_to_get_from_raw_buf;
      } else {
        requested_bytes = remaining_bytes;
      }
      raw_data = get_data_from_csprng_buffer(fips_state, requested_bytes);
      if ( raw_data == NULL) return(bytes_written);
    }
        
   
    if ( !fips_state->perform_fips_test || fips_result == 0) {

      //Check if we can copy data directly to output_buffer, without need to write to buffer fips_state->out_buf
      if ( remaining_bytes >= requested_bytes) {
        memcpy(output_buffer, raw_data, requested_bytes);
        bytes_written += requested_bytes;
        output_buffer += requested_bytes;
        remaining_bytes = output_size - bytes_written;
      } else {
        memcpy(output_buffer, raw_data, remaining_bytes);
        raw_data += remaining_bytes;
        //output_buffer += remaining_bytes;
        //bytes_written = output_size;
        //remaining_bytes = 0;
        bytes_to_put_into_buffer = requested_bytes - remaining_bytes;
        assert(fips_state->out_buf.valid_data_size == 0);
        assert(fips_state->out_buf.total_size - fips_state->out_buf.valid_data_size >= bytes_to_put_into_buffer);
        memcpy(fips_state->out_buf.buf_start + fips_state->out_buf.valid_data_size, raw_data, bytes_to_put_into_buffer);
        fips_state->out_buf.valid_data_size += bytes_to_put_into_buffer;
  
        return output_size;
      }
    }
  }
  return output_size;
} /* -----  end of function fips_approved_csprng_generate  ----- */
//}}}

//{{{ csprng_destroy
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_destroy
 *  Description:  Destroy rng_buf which holds FIPS approved data
 * =====================================================================================
 */
int fips_approved_csprng_destroy (fips_state_type *fips_state) 
{
  int return_value=0;

  if ( fips_state->perform_fips_test ) {
    dump_fips_statistics( &fips_state->fips_ctx.fips_statistics );
  }
  return_value = csprng_destroy( &fips_state->csprng_state);
  destroy_buffer( &fips_state->out_buf);
  destroy_buffer( &fips_state->raw_buf);
  return return_value;

}		/* -----  end of function fips_approved_csprng_destroy ----- */
//}}}  

