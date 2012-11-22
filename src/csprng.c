/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice
Copyright (C) 2011, 2012 Jirka Hladky

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

// {{{ Includes and constants (defines)
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/types.h>  //fstat
#include <sys/stat.h>   //fstat
#include <unistd.h>
#include <math.h>

#include <csprng/helper_utils.h>
#include <csprng/havege.h>
#include <csprng/nist_ctr_drbg.h>
#include <csprng/memt19937ar-JH.h>
#include <csprng/sha1_rng.h>
#include <csprng/http_rng.h>
#include <csprng/csprng.h>
#include <csprng/fips.h>

#if 0
//See function increment_block_BN
#include <openssl/sha.h>
#include <openssl/bn.h>   /* BN_*() */
#include <openssl/err.h>	/* ERR_*() */
#endif

#include <arpa/inet.h>
#include <openssl/rand.h>

//getrlimit
#include <sys/time.h>
#include <sys/resource.h>


#define BYTES_PRODUCED_BY_SHA1 20
#define HTTP_RNG_BUFFER_SIZE 16384
//TODO: How to deal with the fact that pthread_cond_timedwait does not stop after interrupt??
//http://fixunix.com/unix/257454-pthread_cond_timedwait-signal-handler.html
#define HTTP_ZERO_ROUNDS_THRESHOLD 3

#define DETAIL_DEBUG
#define MIN_BUFFER_SIZE 4096 

//#define STRINGIFY(x) #x
//#define TOSTRING(x) STRINGIFY(x)
//#define AT "LINE NUMBER: " TOSTRING(__LINE__) " "

const char* const source_names[SOURCES_COUNT] = { "NONE", "HAVEGE", "SHA1_RNG", "MT_RNG", "HTTP_RNG", "STDIN", "EXTERNAL" };

// }}}

//{{{ static rng_buf_type* init_buffer ( rand_source_type source, rng_state_type rng_state, const char* filename, FILE* fd, const unsigned int size)
static rng_buf_type* init_buffer ( rand_source_type source, rng_state_type rng_state, const char* filename, FILE* fd, const unsigned int size, const char* buffer_name)
{
  if ( source == EXTERNAL ) assert ( filename != NULL);
  if ( filename != NULL )   assert ( source == EXTERNAL);
  assert ( source < SOURCES_COUNT );

  //fprintf ( stderr, "\nTrying to allocate buffer %s of size %u Bytes\n", buffer_name, size);
  rng_buf_type* data;
  struct rlimit rlim;
  unsigned int mlock_limit;

  data = (rng_buf_type*) calloc( 1, sizeof(rng_buf_type));
  if ( data ==NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for buffer of size %lu. Reported error: %s\n", (unsigned long) sizeof(rng_buf_type), strerror(errno));
    return NULL;
  }

  data->buf	= (unsigned char*) calloc ( 1, size );
  if ( data->buf ==NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for buffer of size %u. Reported error: %s\n", size, strerror(errno));
    return NULL;
  }

  errno = 0;
  data->locked = 0;

  //{{{ getrlimit
  if ( getrlimit(RLIMIT_MEMLOCK, &rlim) == 0 ) {
    mlock_limit = rlim.rlim_cur;
    //fprintf(stderr, "INFO:  getrlimit(RLIMIT_MEMLOCK, rlim) reports: current limit %d, maximum (ceiling) %d.\n", rlim.rlim_cur, rlim.rlim_max);
    mlock_limit /= 4;
  } else {
    mlock_limit = 16384;
    fprintf (stderr, "\nWARNING: Function init_buffer: getrlimit(RLIMIT_MEMLOCK, rlim) has failed. Using %d as default limit. Reported error: %s\n", mlock_limit,  strerror (errno) );
  }
  //}}}

  if ( size <= mlock_limit ) {
    if ( mlock(data->buf, size ) == 0 ) {
      data->locked = 1;
    } else {
      fprintf (stderr, "\nWARNING: Function init_buffer: cannot lock buffer to RAM (preventing that memory from being paged to the swap area)\n"
          "\tSize of buffer is %u Bytes. Reported error: \"%s\". See man -S2 mlock for the interpretation.\n", size, strerror (errno) );
    }
  }

  data->total_size = size;
  data->valid_data_size = 0;
  data->buf_start = data->buf;
  data->fd = fd;
  data->eof = 0;
  data->source = source;
  data->rng_state = rng_state;
  data->bytes_in = 0LLU;
  data->bytes_out = 0LLU;

  if ( source == EXTERNAL && filename != NULL ) {
    data->filename = strdup (filename);  //malloc !
  } else {
    data->filename = NULL;
  }

  if ( buffer_name != NULL ) {
    data->buffer_name = strdup(buffer_name); //malloc !
  } else {
    data->buffer_name = NULL;
  }

  return data;
}
//}}}

//{{{ static void destroy_buffer ( rng_buf_type* data )
static void destroy_buffer ( rng_buf_type* data )
{
  if ( data == NULL ) return;

  if ( data->buffer_name != NULL ) {
    free(data->buffer_name);
  }

  if ( data->filename != NULL ) {
    free(data->filename);
  }

  memset(data->buf, 0, data->total_size );
  if ( data->locked == 1 ) {
    if ( munlock(data->buf, data->total_size ) != 0) {
      fprintf (stderr, "\nWARNING: Function destroy_buffer: cannot unlock buffer from RAM (lock prevents memory from being paged to the swap area).\n"
          "Size of buffer is %u Bytes. Reported error: %s\n", data->total_size, strerror (errno) );
    }
  }

  free (data->buf);
  memset(data, 0, sizeof(rng_buf_type) );
  free (data);
}		/* -----  end of static function destroy_buffer  ----- */
//}}}

//{{{ static int fill_buffer_using_file ( rng_buf_type* data )
static void fill_buffer_using_file ( rng_buf_type* data )
{
  int bytes_read;
  int bytes_to_fill_the_buffer;
  
  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  if ( data->eof == 1 ) return;
  
  //Since one file stream can be used for mutliple buffers we need to explicitly check for feof
  if (feof(data->fd)) return;

  // 2. Fill buffer
  bytes_to_fill_the_buffer = data->total_size - data->valid_data_size;
  bytes_read = fread ( data->buf_start + data->valid_data_size, 1, bytes_to_fill_the_buffer, data->fd);
  data->valid_data_size += bytes_read;
  data->bytes_in += bytes_read;

  if ( bytes_read < bytes_to_fill_the_buffer ) {
    if (feof(data->fd)) {
      if ( data->source == EXTERNAL ) {
        fprintf(stderr,"#fill_buffer_using_file: EOF detected for file %s\n", data->filename);
      } else {
        fprintf(stderr,"#fill_buffer_using_file: EOF detected for STDIN\n");
      }
      data->eof = 1;
    } else {
      fprintf(stderr,"#fill_buffer_using_file: ERROR: %s\n", strerror(errno));
    }
    fprintf(stderr, "#fill_buffer_using_file: Bytes read %d, bytes requested %d\n", bytes_read, bytes_to_fill_the_buffer);
    return;
  }
}		/* -----  end of function fill_buffer_using_file  ----- */
//}}}

//{{{ static void fill_buffer_using_HAVEGE ( rng_buf_type* data )
static void fill_buffer_using_HAVEGE ( rng_buf_type* data )
{
  size_t blocks_read;
  size_t blocks_to_fill_the_buffer;
  DATA_TYPE *p;

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;
  if ( data->eof == 1 ) return;

  // 2. Fill buffer
  // Allign to be multiple of sizeof(DATA_TYPE)
  blocks_to_fill_the_buffer = ( data->total_size - data->valid_data_size ) / sizeof(DATA_TYPE);
  /*
  if ( blocks_to_fill_the_buffer * sizeof(DATA_TYPE) !=  data->total_size - data->valid_data_size ) {
    fprintf(stderr, "WARNING: fill_buffer_using_HAVEGE: blocks_to_fill_the_buffer %zu * %zu != total_size -valid_data_size %u. "
        "Expecting total_size -valid_data_size to be multiple of %zu.\n", 
        blocks_to_fill_the_buffer, sizeof(DATA_TYPE), data->total_size - data->valid_data_size, sizeof(DATA_TYPE));
  }
  */
  p = (DATA_TYPE *) (data->buf_start + data->valid_data_size);
  blocks_read = generate_words_using_havege (p, blocks_to_fill_the_buffer);
  data->valid_data_size += ( sizeof(DATA_TYPE) * blocks_read );
  data->bytes_in += ( sizeof(DATA_TYPE) * blocks_read );
  //fwrite(p, sizeof(DATA_TYPE), blocks_read, stdout);

  if ( blocks_read != blocks_to_fill_the_buffer ) {
    fprintf(stderr, "ERROR: #fill_buffer_using_HAVEGE: Generated %zu %zu-bit blocks,  requested %zu %zu-bit blocks.\n",
       blocks_read, 8*sizeof(DATA_TYPE), blocks_to_fill_the_buffer, 8*sizeof(DATA_TYPE));
    data ->eof = 1;
  }

}		/* -----  end of function fill_buffer_using_HAVEGE  ----- */
//}}}

//{{{ static void fill_buffer_using_SHA ( rng_buf_type* data )
static void fill_buffer_using_SHA ( rng_buf_type* data )
{
  int bytes_read;
  int bytes_to_fill_the_buffer;

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;
  if ( data->eof == 1 ) return;

  // 2. Fill buffer
  bytes_to_fill_the_buffer = ( data->total_size - data->valid_data_size );
  //Allign to be multiple of BYTES_PRODUCED_BY_SHA1 
  bytes_to_fill_the_buffer -= bytes_to_fill_the_buffer % BYTES_PRODUCED_BY_SHA1;
  bytes_read = generate_using_SHA1 (data->rng_state.sha, data->buf_start + data->valid_data_size, bytes_to_fill_the_buffer);
  data->valid_data_size += bytes_read;
  data->bytes_in += bytes_read;

  if ( bytes_read != bytes_to_fill_the_buffer ) {
    fprintf(stderr, "ERROR: #fill_buffer_using_SHA: Bytes generated %d, bytes requested %d\n", bytes_read, bytes_to_fill_the_buffer);
    data->eof = 1;
  }

}
//}}}

//{{{ static void fill_buffer_using_HTTP ( rng_buf_type* data )
static void fill_buffer_using_HTTP ( rng_buf_type* data )
{
  int bytes_read;
  int bytes_to_fill_the_buffer;
  const int bytes_requested = data->total_size - data->valid_data_size;
  static int zero_round = 0;        //Counts how many times we got no bytes
  
  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  if ( data->eof == 1 ) return;
  
  //http_random_status returns the number of active threads
  //if ( http_random_status(data->rng_state.http, 0)<=0 ) {
  //  data->eof = 1;
  //  return;
  //}

  // 2. Fill buffer
  do {
    bytes_to_fill_the_buffer = data->total_size - data->valid_data_size;
    bytes_read = http_random_generate(data->rng_state.http, data->buf_start + data->valid_data_size, bytes_to_fill_the_buffer, HTTP_TIMEOUT_IN_SECONDS);
    data->valid_data_size += bytes_read;
    data->bytes_in += bytes_read;

    //TODO: check if http_random_generate was stop because of the interrupt (signal)
    if ( bytes_read < bytes_to_fill_the_buffer ) {
      if ( bytes_read == 0 ) {
        ++zero_round;
        fprintf(stderr,"WARNING: fill_buffer_using_HTTP: got 0 bytes from HTTP_RNG already %d times in row.\n", zero_round);
        if ( zero_round >= HTTP_ZERO_ROUNDS_THRESHOLD ) {
          fprintf(stderr,"WARNING: fill_buffer_using_HTTP: got 0 bytes from HTTP_RNG %d times in row. Closing HTTP_RNG generator.\n", zero_round);
          //TODO: should we mark EOF at this stage????
          data->eof = 1;
          break;
        }
      } else {
        zero_round = 0;
      }
    }
  } while ( data->total_size - data->valid_data_size > 0 );

  if ( data->total_size - data->valid_data_size > 0 ) fprintf(stderr,"WARNING: fill_buffer_using_HTTP: Bytes read %d, bytes requested %d\n", bytes_read, bytes_requested);
  return;
}
//}}}

//{{{ static void fill_buffer_using_MT_RNG ( rng_buf_type* data )
static void fill_buffer_using_MT_RNG ( rng_buf_type* data )
{
  int blocks_read;
  int blocks_to_fill_the_buffer;
  uint32_t *p;

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;
  if ( data->eof == 1 ) return;

  // 2. Fill buffer
  //Allign to be multiple of 4 
  blocks_to_fill_the_buffer = ( data->total_size - data->valid_data_size ) / 4;
  p = (uint32_t *) (data->buf_start + data->valid_data_size);
  blocks_read = MEMT_fill_buffer(data->rng_state.memt, p, blocks_to_fill_the_buffer);
  data->valid_data_size += 4 * blocks_read;
  data->bytes_in += 4 * blocks_read;

  if ( blocks_read != blocks_to_fill_the_buffer ) {
    fprintf(stderr, "ERROR: #fill_buffer_using_MT_RNG: Generated %d 32-bit blocks,  requested %d 32-bit blocks.\n", blocks_read, blocks_to_fill_the_buffer);
    data ->eof = 1;
  }

}
//}}}

//{{{ static const unsigned char* get_data_from_RNG_buffer ( rng_buf_type* data, int size )
static const unsigned char* get_data_from_RNG_buffer ( rng_buf_type* data, unsigned int size )
{
  //assert ( data->source < SOURCES_COUNT ); => Moved to init_buffer function
  //assert( size <= data->total_size);

  unsigned char* temp;
  //unsigned int old_valid = data->valid_data_size;

  if ( size > data->valid_data_size ) {
    switch (data->source) {
      case HAVEGE:
        fill_buffer_using_HAVEGE (data);
        break;
      case SHA1_RNG:
        fill_buffer_using_SHA (data);
        break;
      case HTTP_RNG:
        fill_buffer_using_HTTP (data);
        break;
      case MT_RNG:
        fill_buffer_using_MT_RNG (data);
        break;
      case STDIN:
      case EXTERNAL:
        fill_buffer_using_file ( data );
        break;
      default:
        fprintf( stderr, "ERROR: get_data_from_RNG_buffer: Unsupported data source '%s' for buffer %s.\n", source_names[data->source], data->buffer_name );
        return (NULL);
        //TODO: FIPS validation at this stage??? Or directly in each method???
    }

    //fprintf ( stderr, "get_data_from_RNG_buffer: requested %u Bytes, provided %u Bytes\n", size, data->valid_data_size - old_valid);


    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "ERROR: get_data_from_RNG_buffer: Failed to get requested bytes for buffer %s.\n", data->buffer_name );
      fprintf ( stderr, "ERROR:                           Bytes requested %d, bytes available %d.\n", size, data->valid_data_size );
      return (NULL);
    }
  }

  data->valid_data_size -= size;
  data->bytes_out += size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;
  //if ( ((unsigned long)data->buf_start & 7) != 0 ) {
  //  fprintf(stderr, "INFO: get_data_from_RNG_buffer. Not 8-byte alligned %p\n",  data->buf_start);
  //} 

  return(temp);
}
//}}}

//{{{ static inline unsigned long int random_number_in_range( rng_buf_type* rng_buf, const unsigned int max) {
// We will use uniform distribution <1, max>. 
// Last value max will have slightly higher frequency
// 0 indicates ERROR condition
static inline unsigned long int random_number_in_range( rng_buf_type* rng_buf, const unsigned int max) {
  unsigned long int result;

#if  1
  const unsigned char* raw;
  uint32_t* random_number;
  const unsigned long int bucket = UINT32_MAX / max;
  raw =  get_data_from_RNG_buffer( rng_buf, 4 );
  if ( raw == NULL ) return 0;
  random_number = (uint32_t*) (raw) ;
  result =  1 + *random_number / bucket ;
#else
  const unsigned long int bucket = RAND_MAX / max;
  int random_number;
  random_number = random() ;
  result =  1 + random_number / bucket ;
#endif
  if ( result > max ) result = max;
  return result;
}
//}}}

//{{{ static int fill_buffer_using_csprng (fips_state_type* fips_state)
static int fill_buffer_using_csprng (fips_state_type* fips_state)
{
  unsigned long int generated_bytes;
  unsigned long int bytes_to_generate;
  unsigned long int csprng_blocks_to_generate;             //Number of CSPRNG blocks (NIST_BLOCK_OUTLEN_BYTES in one block) to generate 
  rng_buf_type* data = fips_state->raw_buf;
  static unsigned long int remaining_bytes_to_reseed = 0;  //Bytes to be generated without need for reseed
  uint8_t reseed;
  uint8_t reseed_possible;

//#define fill_buffer_using_csprng_DEBUG
#ifdef fill_buffer_using_csprng_DEBUG
  static double sum=0.0;
  static double sum_count=0.0;
  static double total=0.0;
  static double total_count=0.0;
  unsigned long int csprng_blocks;
#endif  


  if ( fips_state->csprng_state->mode.max_number_of_csprng_blocks * NIST_BLOCK_OUTLEN_BYTES > NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) {
    reseed_possible = 1;
  } else {
    reseed_possible = 0;
  }

  if ( remaining_bytes_to_reseed == 0 ) {
    if ( fips_state->csprng_state->mode.random_length_of_csprng_generated_bytes == 0 ) {
      csprng_blocks_to_generate  = fips_state->csprng_state->mode.max_number_of_csprng_blocks;
    } else {
      csprng_blocks_to_generate = random_number_in_range( 
          fips_state->csprng_state->random_length_buf, fips_state->csprng_state->mode.max_number_of_csprng_blocks);
#ifdef fill_buffer_using_csprng_DEBUG
      sum_count++;
      sum+=csprng_blocks_to_generate;
      fprintf(stderr,"Number of planned CSPRNG blocks:\t %lu,\t Mean: %g\t Count: %g\t Planned blocks: %g\n", csprng_blocks_to_generate, sum/sum_count, sum_count, sum);
#endif

    }
    remaining_bytes_to_reseed = csprng_blocks_to_generate * NIST_BLOCK_OUTLEN_BYTES;
  }


  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  if ( data->eof == 1 ) return 1;


  // 2. Fill buffer
  if ( reseed_possible && remaining_bytes_to_reseed > NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) {
    bytes_to_generate =  NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST;
    reseed = 0;
  } else {
    bytes_to_generate = remaining_bytes_to_reseed;
    reseed = 1;
  }

  if ( data->valid_data_size + bytes_to_generate > data->total_size ) {
    fprintf(stderr, "WARNING: fill_buffer_using_csprng: Number of Bytes to generate %lu does not fit to the output buffer with free space of %u Bytes. "
        "Total buffer size is %u Bytes.\n", 
        bytes_to_generate, data->total_size - data->valid_data_size,  data->total_size);
    return 1;
  }

  while ( data->valid_data_size + bytes_to_generate <= data->total_size ) {

    generated_bytes = csprng_generate ( fips_state->csprng_state, data->buf_start + data->valid_data_size, bytes_to_generate, reseed);

    if ( generated_bytes != bytes_to_generate ) {
      data->eof = 1;
      return 1;
    }
    data->valid_data_size += generated_bytes;
    data->bytes_in += generated_bytes;

#ifdef fill_buffer_using_csprng_DEBUG
    if ( fips_state->csprng_state->mode.random_length_of_csprng_generated_bytes == 1 ) {
      csprng_blocks = bytes_to_generate / NIST_BLOCK_OUTLEN_BYTES;
      total += csprng_blocks;
      total_count++;
      fprintf(stderr,"Generated CSPRNG blocks:\t %lu,\t Mean: %g\t Count: %g\t Generated blocks: %g\n", csprng_blocks, total/total_count, total_count, total);
    }
#endif    

    if ( reseed ) {
      if ( fips_state->csprng_state->mode.random_length_of_csprng_generated_bytes == 0 ) {
        csprng_blocks_to_generate  = fips_state->csprng_state->mode.max_number_of_csprng_blocks;
      } else {
        csprng_blocks_to_generate = random_number_in_range( 
            fips_state->csprng_state->random_length_buf, fips_state->csprng_state->mode.max_number_of_csprng_blocks);
#ifdef fill_buffer_using_csprng_DEBUG
        sum_count++;
        sum+=csprng_blocks_to_generate;
        fprintf(stderr,"Number of planned CSPRNG blocks:\t %lu,\t Mean: %g\t Count: %g\t Planned blocks: %g\n", csprng_blocks_to_generate, sum/sum_count, sum_count, sum);
#endif
      }
      remaining_bytes_to_reseed = csprng_blocks_to_generate * NIST_BLOCK_OUTLEN_BYTES;
    } else {
      remaining_bytes_to_reseed -= bytes_to_generate;
    }

    if ( reseed_possible && remaining_bytes_to_reseed > NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) {
      bytes_to_generate =  NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST;
      reseed = 0;
    } else {
      bytes_to_generate = remaining_bytes_to_reseed;
      reseed = 1;
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
get_data_from_csprng_buffer ( fips_state_type* fips_state, unsigned int size)
{
  unsigned char* temp;
  rng_buf_type* data = fips_state->raw_buf;
  if ( size > data->valid_data_size ) {
    fill_buffer_using_csprng (fips_state);
    if ( size > data->valid_data_size ) {
      fprintf ( stderr, "ERROR: get_data_from_csprng_buffer: Failed to get requested bytes for buffer %s.\n", data->buffer_name );
      fprintf ( stderr, "ERROR:                              Bytes requested %d, bytes available %d.\n", size, data->valid_data_size );
      return (NULL);
    }
  }

  data->valid_data_size -= size;
  data->bytes_out += size;
  temp = data->buf_start;
  data->buf_start = data->buf_start + size;
  //if ( ((unsigned long)data->buf_start & 7) != 0 ) {
  //  fprintf(stderr, "INFO: get_data_from_RNG_buffer. Not 8-byte alligned %p\n",  data->buf_start);
  //} 

  return(temp);
}		/* -----  end of function get_data_from_csprng_buffer  ----- */
//}}}

//{{{ static void destroy_seed(char* seed, char* locked, unsigned int* size)
static void destroy_seed(unsigned char* seed, char* locked, unsigned int* size)
{
  if ( seed == NULL ) {
    fprintf(stderr, "ERROR: destroy_seed function. First argument must not be NULL.\n");
    return;
  }

  memset(seed, 0, *size);
  if ( *locked == 1 ) {
    *locked = 0;
    if ( munlock(seed, *size) != 0) {
      fprintf (stderr, "\nWARNING: Function destroy_seed: cannot unlock buffer from RAM (lock prevents memory from being paged to the swap area).\n"
          "Size of buffer is %u Bytes. Reported error: %s\n", *size, strerror (errno) );
    }
  }
  free (seed);
  seed = NULL;
  *size = 0;

}
//}}}

//{{{ static int increment_block( uint8_t s[], int len, uint32_t incr)
static int increment_block( uint8_t s[], int len, uint32_t incr) {
  //Strategy: work on bytes. Use double word to perform the addition

  if (len < 4) {
    fprintf(stderr, "ERROR: function increment_block requires len>=4. Got value %d\n", len);
    return 1;
  };
  
  int i;
  uint16_t temp=0;
  uint32_t be_incr = htonl(incr);  //Convert incr to BIG ENDIAN
  uint8_t* p = (uint8_t*) &be_incr;

#ifdef DETAIL_DEBUG
//    dump_hex_byte_string(s, len, "increment_block, input: \t");
//    fprintf(stderr, "increment_block, incr: \t%"PRIu32"\n", incr);
//    dump_hex_byte_string(p, 4, "increment_block, incr: \t");
#endif  

  for (i = 3; i >=0; --i) {
    temp += (uint16_t) s[len-4+i] + p[i];
    s[len-4+i] = (uint8_t)temp & 0xff;
  //  fprintf(stderr, "increment_block, value: \t%"PRIu8"\n", s[len-4+i]);
    temp>>=8;                   //Carry
  //  fprintf(stderr, "increment_block, carry: \t%"PRIu16"\n", temp);
  }
   
  for (i=len-5; i >=0; --i) {
    temp += (uint16_t) s[i];
    s[i] = (uint8_t)temp & 0xff;
    temp>>=8;
    if ( temp == 0 ) goto end_of_increment_block;
  }

end_of_increment_block:
#ifdef DETAIL_DEBUG
//    dump_hex_byte_string(s, len, "increment_block, output: \t");
#endif  
return 0;
}
//}}}

//{{{ static int increment_block_BN (unsigned char *s, unsigned int len, unsigned long int incr)
#if 0
static int increment_block_BN (unsigned char *s, unsigned int len, unsigned long int incr)
{
  BN_CTX* context;
  BIGNUM input;
  int i;
  int return_status = 1; //indicates an error

#ifdef DETAIL_DEBUG
    dump_hex_byte_string(s, len, "increment_block, input: \t");
//    fprintf(stderr, "increment_block, incr: \t%lu\n", incr);
    uint32_t be_incr = htonl(incr);  //Convert incr to BIG ENDIAN
    uint8_t* p = (uint8_t*) &be_incr;
    dump_hex_byte_string(p, 4, "increment_block, incr: \t");
#endif  

	context = BN_CTX_new();
  if ( context == NULL ) {
    fprintf(stderr, "ERROR: BN_CTX_new\n");
    goto BN_CTX_free_label;
  }

  BN_init(&input);

	if ( BN_bin2bn(s, len, &input) == NULL ) {
    fprintf(stderr, "ERROR: BN_bin2bn\n");
    goto BN_clear_label;
  }

//  fprintf(stderr,"BN_num_bytes(&input) %d\n", BN_num_bytes(&input) );
//  fprintf(stderr,"BN_num_bits(&input) %d\n", BN_num_bits(&input) );


  if ( BN_add_word(&input, incr) == 0 ) {
    fprintf(stderr, "ERROR: BN_add_word\n");
    goto BN_clear_label;
  }


  if ( BN_num_bytes(&input) > len ) {
    if ( BN_mask_bits (&input, 8 * len ) == 0 ) {
    fprintf(stderr, "ERROR: BN_mask_bits\n");
    goto BN_clear_label;
    }
  }
//  fprintf(stderr,"BN_num_bits(output) %d\n", BN_num_bits(&input) );
//  fprintf(stderr,"BN_num_bytes(output) %d\n", BN_num_bytes(&input) );

  i = BN_num_bytes(&input);
  assert( len >= i );

  if ( len > i) memset(s,0, len-i);

  if ( BN_bn2bin(&input, s+(len-i)) != i ) {
    fprintf(stderr, "ERROR: BN_bn2bin\n");
    goto BN_clear_label;
  }

#ifdef DETAIL_DEBUG
    dump_hex_byte_string(s, len, "increment_block, output: \t");
#endif  
  
  return_status = 0;  //SUCESS

BN_clear_label:
  BN_clear(&input);

BN_CTX_free_label:
  BN_CTX_free (context);
  return return_status;

}
#endif
//}}}

//{{{ unsigned char* create_seed(const char* filename, const unsigned int size, char* locked, unsigned int* allocated_size)
//*locked is the output. It specifies if memory was locked using mlock call
//*allocated_size is the output. *allocated_size>=0, *allocated_size is alligned on 20 bytes boundary
unsigned char* create_seed(const char* filename, unsigned int size, char* locked, unsigned int* allocated_size) {
  FILE* randomDataFile;
  int ret;
  unsigned char *data, *p, *p1, *p2;
  unsigned char sha1_md[SHA_DIGEST_LENGTH], sha1_input[SHA_DIGEST_LENGTH], openssl_rand[SHA_DIGEST_LENGTH];
  unsigned long int i,j, requested_size;
  unsigned char* return_status = NULL;
  struct rlimit rlim;
  unsigned int mlock_limit;


  assert (locked != NULL);
  assert (allocated_size != NULL);
  
  *locked = 0;
  *allocated_size = 0;
  requested_size = size;
  //SHA-1 return 20 bytes. We will feed it with blocks of length of 20 as well. Allocate memory
  if (size % SHA_DIGEST_LENGTH ) size += ( SHA_DIGEST_LENGTH - size % SHA_DIGEST_LENGTH );
  assert(size > requested_size);

  data = (unsigned char*) malloc ( size );
  if ( data == NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for buffer of size %u. Reported error: %s\n", size, strerror(errno));
    return NULL;
  } else {
    *allocated_size = size;
  }

  //{{{ getrlimit
  if ( getrlimit(RLIMIT_MEMLOCK, &rlim) == 0 ) {
    mlock_limit = rlim.rlim_cur;
    //fprintf(stderr, "INFO:  getrlimit(RLIMIT_MEMLOCK, rlim) reports: current limit %d, maximum (ceiling) %d.\n", rlim.rlim_cur, rlim.rlim_max);
  } else {
    mlock_limit = 16384;
    fprintf (stderr, "\nWARNING: Function init_buffer: getrlimit(RLIMIT_MEMLOCK, rlim) has failed. Using %d as default limit. Reported error: %s\n", mlock_limit,  strerror (errno) );
  }
  //}}}

  //Prevent buffer from being swapped out
  if ( size <= mlock_limit ) {
    if ( mlock(data, size ) == 0 ) {
      *locked = 1;
    } else {
      fprintf (stderr, "\nWARNING: Cannot lock buffer to RAM (preventing that memory from being paged to the swap area)\n"
          "Size of buffer is %u Bytes. Reported error: %s\n", size, strerror (errno) );
    }
  }

  //Open file
  randomDataFile = fopen(filename, "r");
  if ( randomDataFile == NULL ) {
    fprintf(stderr, "ERROR: Cannot open file %s for reading. Reported error: %s\n", filename, strerror(errno));
    goto free_buffer;
  }

  //Read data
  ret = fread ( data, size, 1, randomDataFile);

  if ( ret != 1 ) {
    if (feof(randomDataFile)) {
      fprintf(stderr,"ERROR: EOF detected for file %s when trying to read %u bytes.\n", filename, size);
    } else {
      fprintf(stderr,"ERROR: Reading of %u bytes from file %s has failed. Reported error: %s\n", size, filename, strerror(errno));
    }
    fprintf(stderr, "ERROR: fread error for file %s when trying to read %u bytes.\n", filename, size);
    goto close_file;
  }

  ret = fclose(randomDataFile);
  if ( ret ) {
    fprintf(stderr, "WARNING: Cannot close file %s. Reported error: %s\n", filename, strerror(errno));
  }
  //OPENSSL cryptographically strong pseudo-random bytes
  if (RAND_get_rand_method() == NULL) RAND_set_rand_method(RAND_SSLeay());

  //Process data through SHA-1 and XOR data with SHA-1 sum
  p = data;
  for ( i=0; i < size / SHA_DIGEST_LENGTH; ++i) {
    memcpy(sha1_input, p, SHA_DIGEST_LENGTH);
    if ( increment_block( sha1_input, SHA_DIGEST_LENGTH, 2*i+1) == 1 ) {
      fprintf ( stderr, "ERROR: increment_block function has failed.\n" );
      goto free_buffer;
    }
 
    p1 = SHA1(sha1_input, SHA_DIGEST_LENGTH, sha1_md);

    if ( p1 != sha1_md ) {
      fprintf ( stderr, "ERROR: SHA1 function has failed.\n" );
      goto free_buffer;
    }

    if ( RAND_bytes(openssl_rand, SHA_DIGEST_LENGTH) == 0 ) {
      fprintf ( stderr, "ERROR: RAND_bytes function has failed.\n" );
      goto free_buffer;
    }

    p2 = p;
    for (j=0; j<SHA_DIGEST_LENGTH; ++j) {
      //XOR
      *p2 ^= sha1_md[j];
      *p2 ^= openssl_rand[j];
      ++p2;
    }
#ifdef DETAIL_DEBUG
//    dump_hex_byte_string(p, SHA_DIGEST_LENGTH, "Seed: \t");
#endif  

    assert ( p2 == p + SHA_DIGEST_LENGTH);
    p += SHA_DIGEST_LENGTH;
  }
  assert ( p == data + size );

  return_status = data;
  goto clean_memory;

close_file:
  fprintf ( stderr, "ERROR: Function create_seed has failed.\n" );
  ret = fclose(randomDataFile);
  if ( ret ) {
    fprintf(stderr, "WARNING: Cannot close file %s. Reported error: %s\n", filename, strerror(errno));
  }
free_buffer:
  assert( *allocated_size == size);
  destroy_seed(data, locked, allocated_size);
clean_memory:  
  memset(sha1_md, 0, sizeof(sha1_md));
  memset(sha1_input, 0, sizeof(sha1_input));
  memset(openssl_rand, 0, sizeof(openssl_rand));
  return return_status;

}
//}}}

//{{{ function open_file_for_reading(const char* filename)
static FILE* open_file_for_reading(const char* filename) {

  FILE* fd;

  if ( filename == NULL ) {
    fprintf(stderr, "ERROR: open_file_for_reading - no input filename was provided.\n");
    return NULL;
  } else {
    fd = fopen ( filename, "r" );
    if ( fd == NULL ) fprintf(stderr, "ERROR: Cannot open file '%s' for reading. Reported error: %s\n", filename, strerror(errno));
  }
  return fd;
}
//}}}

//{{{csprng_state_type* csprng_initialize ( const mode_of_operation_type* mode_of_operation)
csprng_state_type* csprng_initialize( const mode_of_operation_type* mode_of_operation)
{
  int error;
  char buf[2048];
  int size;
  int max;
  unsigned int seed_len[3]={0};   //0 => for Mersenne Twister
                                  //1 => for SHA-1
                                  //2 => Total seed length
  uint8_t *seed, *seed_p;
  char locked;                  //Was seed locked?
  unsigned int allocated_size;  //Number of bytes allocated for seed.
  rng_state_type rng_state;
  csprng_state_type* csprng_state;
  char* QRBG_RNG_login_name;       //User name for random.irb.hr
  char* QRBG_RNG_passwd;           //Password for  random.irb.hr
  char HTTP_source_bitmask;        //source bitmask for http_random_init 

  //{{{ Init csprng_state, do sanity checks
  assert ( mode_of_operation->entropy_source   < SOURCES_COUNT );
  assert ( mode_of_operation->add_input_source < SOURCES_COUNT );

  if ( mode_of_operation->entropy_source   == EXTERNAL ) {
    assert( mode_of_operation->filename_for_entropy != NULL );
  } else {
    assert( mode_of_operation->filename_for_entropy == NULL );
  }

  if ( mode_of_operation->add_input_source == EXTERNAL ) {
    assert( mode_of_operation->filename_for_additional != NULL);
  } else {
    assert( mode_of_operation->filename_for_additional == NULL);
  }

  csprng_state = (csprng_state_type*) calloc( 1, sizeof(csprng_state_type));
  if ( csprng_state ==NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for csprng_state_type variable"
       " of size %zu. Reported error: %s\n", sizeof(csprng_state_type), strerror(errno));
    return NULL;
  }

  csprng_state->mode = *mode_of_operation;
  csprng_state->mode.max_number_of_csprng_generated_bytes = csprng_state->mode.max_number_of_csprng_blocks * NIST_BLOCK_OUTLEN_BYTES;

  //These values are important to correctly call nist_ctr_drbg_destroy
  csprng_state->HAVEGE_initialized = 0;
  csprng_state->sha = NULL;
  csprng_state->memt = NULL;
  csprng_state->ctr_drbg = NULL;
  csprng_state->mode.filename_for_entropy = NULL;     //We will create deep copy when needed later
  csprng_state->mode.filename_for_additional = NULL;  //We will create deep copy when needed later
  csprng_state->file_for_entropy_buf = NULL;
  csprng_state->file_for_additional_buf = NULL;
  csprng_state->random_length_buf = NULL;
  csprng_state->entropy_buf = NULL;
  csprng_state->add_input_buf = NULL;
  csprng_state->entropy_tot = 0;
  csprng_state->additional_input_generate_tot = 0;
  csprng_state->additional_input_reseed_tot = 0;

  if ( csprng_state->mode.entropy_source == EXTERNAL || csprng_state->mode.add_input_source == EXTERNAL ) {  
    if ( csprng_state->mode.file_read_size < 16 ||  csprng_state->mode.file_read_size>65536 ) {
      fprintf(stderr, "ERROR: csprng_initialize: expecting file_read_size to be in range <16, 65536> but got %d \n", csprng_state->mode.file_read_size);
      goto error_detected_initialize;
    }
  }

  if ( csprng_state->mode.use_df ) {
    if ( csprng_state->mode.add_input_source != NONE ) {
      csprng_state->entropy_length = NIST_BLOCK_OUTLEN_BYTES;  //AES-128, 128 bits ~ 16 bytes 
      csprng_state->additional_input_length_generate = NIST_BLOCK_SEEDLEN_BYTES; //AES-128, 2 *128 bits ~ 64 bytes
      csprng_state->additional_input_length_reseed = NIST_BLOCK_OUTLEN_BYTES; //AES-128, 128 bits ~ 16 bytes
    } else {
      csprng_state->entropy_length = NIST_BLOCK_SEEDLEN_BYTES; //AES-128, 2 *128 bits ~ 64 bytes
      csprng_state->additional_input_length_generate = 0;
      csprng_state->additional_input_length_reseed = 0;
    }
  } else {
    csprng_state->entropy_length = NIST_BLOCK_SEEDLEN_BYTES; //AES-128, 2 *128 bits ~ 64 bytes
    if ( csprng_state->mode.add_input_source != NONE ) {
      csprng_state->additional_input_length_generate = NIST_BLOCK_SEEDLEN_BYTES; //AES-128, 2 *128 bits ~ 64 bytes
      csprng_state->additional_input_length_reseed = NIST_BLOCK_SEEDLEN_BYTES; //AES-128, 2 *128 bits ~ 64 bytes
    } else {
      csprng_state->additional_input_length_generate = 0;
      csprng_state->additional_input_length_reseed = 0;
    }
  }
//}}}  

  //{{{ Open files if needed
  if ( csprng_state->mode.entropy_source  == EXTERNAL ) {
    //Deep copy - malloc!
    csprng_state->mode.filename_for_entropy = strdup ( mode_of_operation->filename_for_entropy );
    if ( csprng_state->mode.filename_for_entropy == NULL) goto error_detected_initialize;
    csprng_state->file_for_entropy_buf = open_file_for_reading ( csprng_state->mode.filename_for_entropy );
    if ( csprng_state->file_for_entropy_buf == NULL ) goto error_detected_initialize;
  }

  if ( csprng_state->mode.add_input_source == EXTERNAL ) {
    //Deep copy - malloc!
    csprng_state->mode.filename_for_additional = strdup (  mode_of_operation->filename_for_additional );
    if ( csprng_state->mode.filename_for_additional == NULL ) goto error_detected_initialize;
    csprng_state->file_for_additional_buf = open_file_for_reading ( csprng_state->mode.filename_for_additional);
    if ( csprng_state->file_for_additional_buf == NULL )  goto error_detected_initialize;
  }

  //}}}
 
  //{{{ Check if we need STDIN
  if ( csprng_state->mode.entropy_source  == STDIN ) {
    csprng_state->file_for_entropy_buf = stdin;
  }

  if ( csprng_state->mode.add_input_source == STDIN ) {
    csprng_state->file_for_additional_buf = stdin;
  }
  //}}}

  //{{{ Check if files are the same
  csprng_state->are_files_same = 0;

  if ( csprng_state->mode.add_input_source == STDIN && csprng_state->mode.entropy_source  == STDIN ) {
    csprng_state->are_files_same = 1;
  } else {

    if ( csprng_state->file_for_additional_buf != NULL && csprng_state->file_for_entropy_buf != NULL ) {

      int fd_e = fileno(csprng_state->file_for_entropy_buf);
      if ( fd_e == -1 ) {
        fprintf(stderr, "ERROR: fileno has failed for FILE* with path %s. Reported error: %s\n", csprng_state->mode.filename_for_entropy, strerror(errno));
        goto error_detected_initialize;
      }
      int fd_a = fileno(csprng_state->file_for_additional_buf);
      if ( fd_a == -1 ) {
        fprintf(stderr, "ERROR: fileno has failed for FILE* with path %s. Reported error: %s\n", csprng_state->mode.filename_for_additional, strerror(errno));
        goto error_detected_initialize;
      }

      assert (fd_a != fd_e);

      struct stat buf_e;
      if ( fstat(fd_e, &buf_e) != 0 ) {
        fprintf(stderr, "ERROR: fstat has failed for FILE* with path %s. Reported error: %s\n", csprng_state->mode.filename_for_entropy, strerror(errno));
        goto error_detected_initialize;
      }

      struct stat buf_a;
      if ( fstat(fd_a, &buf_a) != 0 ) {
        fprintf(stderr, "ERROR: fstat has failed for FILE* with path %s. Reported error: %s\n", csprng_state->mode.filename_for_additional, strerror(errno));
        goto error_detected_initialize;
      }

      if ( ( buf_e.st_dev == buf_a.st_dev ) && ( buf_e.st_ino ==  buf_a.st_ino ) ) {
        //Files are the same - we will close one. Handle the case where one file is STDIN and another file is external /dev/pts/0 but same as STDIN
        //Close EXTERNAL file
        fprintf(stderr, "INFO: Files '%s' and '%s' are same.\n", 
            csprng_state->mode.entropy_source == EXTERNAL   ? csprng_state->mode.filename_for_entropy : "STDIN stream",
            csprng_state->mode.add_input_source == EXTERNAL ? csprng_state->mode.filename_for_additional : "STDIN stream" );

        if ( csprng_state->mode.add_input_source == EXTERNAL ) {
          if ( fclose( csprng_state->file_for_additional_buf ) ) {
            fprintf(stderr, "ERROR: Cannot close file '%s'.  Reported error: %s\n", csprng_state->mode.filename_for_additional, strerror(errno));
            goto error_detected_initialize;
          }
          fprintf(stderr, "INFO: fd %d for file '%s' has been closed.\n", fd_a, csprng_state->mode.filename_for_additional);
          csprng_state->file_for_additional_buf = csprng_state->file_for_entropy_buf;
        } else if ( csprng_state->mode.entropy_source == EXTERNAL ) {
          if ( fclose( csprng_state->file_for_entropy_buf ) ) {
            fprintf(stderr, "ERROR: Cannot close file '%s'.  Reported error: %s\n", csprng_state->mode.filename_for_entropy, strerror(errno));
            goto error_detected_initialize;
          }
          fprintf(stderr, "INFO: fd %d for file '%s' has been closed.\n", fd_e, csprng_state->mode.filename_for_entropy);
          csprng_state->file_for_entropy_buf = csprng_state->file_for_additional_buf;
        }
        csprng_state->are_files_same = 1;
      }
    }
  }
  //}}} 

  //{{{ Check if need HTTP_RNG and init it
  if ( csprng_state->mode.entropy_source == HTTP_RNG || csprng_state->mode.add_input_source == HTTP_RNG ) {
    QRBG_RNG_login_name = getenv("QRBG_USER");
    QRBG_RNG_passwd     = getenv("QRBG_PASSWD");
    if ( QRBG_RNG_login_name == NULL || QRBG_RNG_passwd == NULL ) {
      fprintf ( stderr, "WARNING: random.irb.hr generators needs login credentials defined in environmental variables QRBG_USER and QRBG_PASSWD.\n" );
      if ( QRBG_RNG_login_name == NULL ) fprintf ( stderr, "WARNING: environmental variable QRBG_USER is not defined.\n");
      if ( QRBG_RNG_passwd == NULL )     fprintf ( stderr, "WARNING: environmental variable QRBG_PASSWD is not defined.\n");

      HTTP_source_bitmask = MASK_HOTBITS | MASK_RANDOM_ORG | MASK_RANDOMNUMBERS_INFO;
      QRBG_RNG_login_name = NULL;
      QRBG_RNG_passwd = NULL;
    } else {
      HTTP_source_bitmask = MASK_HOTBITS | MASK_RANDOM_ORG | MASK_RANDOMNUMBERS_INFO | MASK_QRBG;
    }
    csprng_state->http =  http_random_init(HTTP_source_bitmask, HTTP_RNG_BUFFER_SIZE,
        mode_of_operation->http_random_verbosity, QRBG_RNG_login_name, QRBG_RNG_passwd);
    if ( csprng_state->http==NULL ) {
      fprintf ( stderr, "\nInitialization of the internet based RNG has failed.\n" );
      goto error_detected_initialize;
    }
    if ( unsetenv("QRBG_USER") ) fprintf(stderr, "WARNING: unsetenv(\"QRBG_USER\") failed with %s.\n", strerror(errno));
    if ( unsetenv("QRBG_PASSWD") ) fprintf(stderr, "WARNING: unsetenv(\"QRBG_PASSWD\") failed with %s.\n", strerror(errno));
  }
  //}}}

  //{{{ Check if need HAVEGE and init it
  if ( csprng_state->mode.entropy_source == HAVEGE || csprng_state->mode.add_input_source == HAVEGE ) {
    error = havege_init( csprng_state->mode.havege_instruction_cache_size, csprng_state->mode.havege_data_cache_size, csprng_state->mode.havege_debug_flags); 
    if ( error ) {
      fprintf(stderr, "ERROR: havege_init has returned %d\n",error);
      goto error_detected_initialize;
    }
    csprng_state->HAVEGE_initialized = 1;

    if ( csprng_state->mode.havege_status_flag == 1 ) {
      havege_status(buf, 2048);
      fprintf(stderr,"================HAVEGE STATUS REPORT================\n");
      fprintf(stderr, "%s\n", buf);
      fprintf(stderr,"====================================================\n");
    }
  }
  //}}}

  //{{{ Check if need Mersenne Twister. Deffer initialization till we will check also if SHA-1 is needed as seed will be captured in one step
  if(csprng_state->mode.random_length_of_csprng_generated_bytes ||
     csprng_state->mode.entropy_source == MT_RNG ||
     csprng_state->mode.add_input_source == MT_RNG )
  {
    seed_len[0] = MEMT_N * sizeof(uint32_t);
  } else {
    seed_len[0] = 0;
  }
  //}}}

  //{{{ Check if need SHA-1. Deffer initialization
  if(csprng_state->mode.entropy_source == SHA1_RNG ||
     csprng_state->mode.add_input_source == SHA1_RNG )
  {
    seed_len[1] = SHA1_VECTOR_LENGTH_IN_BYTES;
  } else {
    seed_len[1] = 0;
  }
  //}}}

  //{{{ Initialize Mersenne Twister and SHA-1
  seed_len[2] =  seed_len[0] + seed_len[1];
  if ( seed_len[2] > 0 ) {
    seed = create_seed("/dev/urandom", seed_len[2], &locked, &allocated_size);
    if ( seed == NULL ) goto error_detected_initialize;
    seed_p = seed;
  
    if ( seed_len[0] > 0 ) {
      uint32_t* seed32;
      unsigned int seed_len32;

      assert(seed_len[0]%4 == 0);
      seed_len32 = seed_len[0] / 4;
      seed32 = (uint32_t*) seed;
      seed_p += seed_len[0];
      if ( seed_len32 == 1 ) {
        csprng_state->memt = MEMT_init_genrand(*seed32);
      } else {
        csprng_state->memt = MEMT_init_by_array( seed32, seed_len32);
      }
      if ( csprng_state->memt == NULL ) {
        fprintf ( stderr, "\nInitialization of Mersenne twister has failed.\n" );
        destroy_seed(seed, &locked, &allocated_size);
        goto error_detected_initialize;
      }
    }

    if ( seed_len[1] > 0 ) {
      csprng_state->sha = create_SHA1(seed_p, seed_len[1], 0, BYTES_PRODUCED_BY_SHA1);
      if ( csprng_state->sha == NULL ) {
        fprintf ( stderr, "\nInitialization of SHA-1 RNG has failed.\n" );
        destroy_seed(seed, &locked, &allocated_size);
        goto error_detected_initialize;
      }
      seed_p += seed_len[1];
    }
    assert( seed + seed_len[2] == seed_p);
    destroy_seed(seed, &locked, &allocated_size);
    seed_p = seed;
  }
  //}}}

  //{{{ init buffer to hold the entropy
  memset(&rng_state, 0, sizeof(rng_state));
  switch ( csprng_state->mode.entropy_source ) {
    case STDIN:
    case EXTERNAL:
      if ( csprng_state->are_files_same == 1 ) {
        //Minimize read size to avoid one buffer to read all available input data and other being empty
        size = 16 + csprng_state->entropy_length;
      } else {
        size =  csprng_state->mode.file_read_size + csprng_state->entropy_length;
      }
      break;
    case HAVEGE:
      size = sizeof(DATA_TYPE) + csprng_state->entropy_length;
      if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
      break;
    case SHA1_RNG:
      size = BYTES_PRODUCED_BY_SHA1 + csprng_state->entropy_length;
      if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
      rng_state.sha = csprng_state->sha;
      break;
    case HTTP_RNG:
      //Make the buffer small as HTTP goes to sleep state when too much data is requested - it's waiting for servers to supply the data
      size = sizeof(uint32_t) + csprng_state->entropy_length;
      if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
      rng_state.http = csprng_state->http;
      break;
    case MT_RNG:
      size = sizeof(uint32_t) + csprng_state->entropy_length;
      if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
      rng_state.memt = csprng_state->memt;
      break;
    default:
      fprintf(stderr, "ERROR: Unsupported csprng_state->mode.entropy_source %s in csprng_initialize.\n", source_names[csprng_state->mode.entropy_source] );
      goto error_detected_initialize;
  }

  csprng_state->entropy_buf = init_buffer( csprng_state->mode.entropy_source, rng_state, 
      csprng_state->mode.filename_for_entropy, csprng_state->file_for_entropy_buf, size, "ENTROPY BUF");
  if ( csprng_state->entropy_buf == NULL ) {
    fprintf(stderr, "ERROR: init_buffer for csprng_state->entropy_buf has failed.\n");
    goto error_detected_initialize;
  }
  //}}}

  //{{{ init buffer of random numbers to derive random_length_of_csprng_generated_bytes
  if(csprng_state->mode.random_length_of_csprng_generated_bytes ) {
    size = 1024;
    memset(&rng_state, 0, sizeof(rng_state));
    rng_state.memt = csprng_state->memt;
    csprng_state->random_length_buf = init_buffer( MT_RNG, rng_state, NULL, NULL, size, "RANDOM LENGTH OF CSPRNG GENERATED BYTES BUF");
    if ( csprng_state->random_length_buf == NULL ) {
      fprintf(stderr, "ERROR: init_buffer for csprng_state->random_length_buf has failed.\n");
      goto error_detected_initialize;
    }
  }
  //}}}

  //{{{ init buffer to hold the additional input
  if ( csprng_state->mode.add_input_source != NONE ) {
    memset(&rng_state, 0, sizeof(rng_state));
    if (  csprng_state->additional_input_length_generate >=  csprng_state->additional_input_length_reseed ) {
      max = csprng_state->additional_input_length_generate;
    } else {
      max = csprng_state->additional_input_length_reseed;
    }
    switch ( csprng_state->mode.add_input_source ) {
      case STDIN:
      case EXTERNAL:
        if ( csprng_state->are_files_same == 1 ) {
          //Minimize read size to avoid one buffer to read all available input data and other being empty
          size = 16 + max;
        } else {
          size =  csprng_state->mode.file_read_size + max;
        }
        break;
      case HAVEGE:
        size = sizeof(DATA_TYPE) + max;
        if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
        break;
      case SHA1_RNG:
        size = BYTES_PRODUCED_BY_SHA1 + max;
        if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
        rng_state.sha = csprng_state->sha;
        break;
      case HTTP_RNG:
        //Make the buffer small as HTTP goes to sleep state when too much data is requested - it's waiting for servers to supply the data
        size = sizeof(uint32_t) + csprng_state->entropy_length;
        if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
        rng_state.http = csprng_state->http;
        break;
      case MT_RNG:
        size = sizeof(uint32_t) + max;
        if ( size < MIN_BUFFER_SIZE ) size = MIN_BUFFER_SIZE;
        rng_state.memt = csprng_state->memt;
        break;
      default:
        fprintf(stderr, "ERROR: Unsupported csprng_state->mode.add_input_source %s in csprng_initialize.\n", source_names[csprng_state->mode.add_input_source] );
        goto error_detected_initialize;
  }

    csprng_state->add_input_buf = init_buffer( csprng_state->mode.add_input_source, rng_state, 
        csprng_state->mode.filename_for_additional, csprng_state->file_for_additional_buf, size, "ADDITIONAL INPUT BUF");
    if ( csprng_state->add_input_buf == NULL ) {
      fprintf(stderr, "ERROR: init_buffer for csprng_state->add_input_buf has failed.\n");
      goto error_detected_initialize;
    }
  }
  //}}}

  //{{{ Initialize NIST CTR DRBG  
  error = nist_ctr_initialize();
  if ( error ) {
    fprintf(stderr, "ERROR: nist_ctr_initialize has returned %d\n",error);
    goto error_detected_initialize;
  }
  //}}}

  return csprng_state;

error_detected_initialize:
  fprintf(stderr, "ERROR: csprng_initialize - error detected, freeing up the memory\n");
  csprng_destroy (csprng_state);
  return NULL;
} 		/* -----  end of function csprng_initialize  ----- */
//}}}

//{{{int csprng_instantiate ( csprng_state_type* csprng_state )
int csprng_instantiate ( csprng_state_type* csprng_state )
{
  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;

  //{{{ Instantiate NIST CTR DRBG  
  entropy = get_data_from_RNG_buffer ( csprng_state->entropy_buf, csprng_state->entropy_length );
  if ( entropy == NULL) goto error_detected_instantiate;
#ifdef DETAIL_DEBUG
//  dump_hex_byte_string(entropy, csprng_state->entropy_length, "Init:    \tentropy_input:     \t");
#endif 
  csprng_state->entropy_tot += csprng_state->entropy_length;

  if ( csprng_state->mode.add_input_source != NONE ) {
    additional_input =  get_data_from_RNG_buffer ( csprng_state->add_input_buf, csprng_state->additional_input_length_reseed );
    if ( additional_input == NULL) goto error_detected_instantiate; 
#ifdef DETAIL_DEBUG
//    dump_hex_byte_string(additional_input, csprng_state->additional_input_length_reseed, "Init:    \tadditional_input: \t");
#endif  
    csprng_state->additional_input_reseed_tot +=  csprng_state->additional_input_length_reseed;
  } else {
    additional_input = NULL;
  }

//  dump_hex_byte_string(csprng_state->entropy_buf->buf, csprng_state->entropy_length, "entropy_input: \t");
//  dump_hex_byte_string(entropy, csprng_state->entropy_length, "entropy_input: \t");

  csprng_state->ctr_drbg = nist_ctr_drbg_instantiate(entropy,  csprng_state->entropy_length, NULL, 0, 
      additional_input , csprng_state->additional_input_length_reseed, csprng_state->mode.use_df);
  if ( csprng_state->ctr_drbg == NULL ) {
    fprintf(stderr, "ERROR: nist_ctr_drbg_instantiate has returned NULL pointer. \n");
    goto error_detected_instantiate;
  }
  //}}}

  //{{{ Reseed NIST CTR DRBG
  entropy = get_data_from_RNG_buffer ( csprng_state->entropy_buf, csprng_state->entropy_length );
  if ( entropy == NULL) goto error_detected_instantiate;
#ifdef DETAIL_DEBUG
//  dump_hex_byte_string(entropy, csprng_state->entropy_length, "Init, res: \tentropy_input:     \t");
#endif  
  csprng_state->entropy_tot += csprng_state->entropy_length;

  if ( csprng_state->mode.add_input_source != NONE ) {
    additional_input =  get_data_from_RNG_buffer ( csprng_state->add_input_buf, csprng_state->additional_input_length_reseed );
    if ( additional_input == NULL) goto error_detected_instantiate; 
#ifdef DETAIL_DEBUG
//    dump_hex_byte_string(additional_input, csprng_state->additional_input_length_reseed, "Init, res: \tadditional_input: \t");
#endif  
  } 
  csprng_state->additional_input_reseed_tot +=  csprng_state->additional_input_length_reseed;

  error = nist_ctr_drbg_reseed(csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length_reseed);
  if ( error ) {
    fprintf(stderr, "ERROR: nist_ctr_drbg_reseed has returned %d\n",error);
    goto error_detected_instantiate;
  }
  //}}}

  return 0;

error_detected_instantiate:
  fprintf(stderr, "ERROR: csprng_instantiate - error detected, freeing up the memory\n");
  csprng_destroy (csprng_state);
  return 1;

}
//}}}

//{{{ csprng_generate
/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_generate
 *  Description:  Generate data using csprng
 * =====================================================================================
 */
int
csprng_generate ( csprng_state_type* csprng_state, unsigned char* output_buffer, unsigned int output_size, uint8_t reseed )
{
  // size is in Bytes. Ideally,  output_size is integer multiply of NIST_BLOCK_OUTLEN_BYTES
  
  int error;
  const unsigned char* entropy = NULL;
  const unsigned char* additional_input = NULL;

  //fprintf(stderr, "csprng_generate: bytes requested %u, reseed %s\n", output_size, (reseed ) ? "YES" : "NO");

  if ( csprng_state->additional_input_length_generate ) {
    additional_input = get_data_from_RNG_buffer ( csprng_state->add_input_buf, csprng_state->additional_input_length_generate );
    if ( additional_input == NULL) return(1);
    //dump_hex_byte_string(additional_input, csprng_state->additional_input_length_generate, "Generate: \tadditional_input: \t");
  
    csprng_state->additional_input_generate_tot += csprng_state->additional_input_length_generate;
    error = nist_ctr_drbg_generate( csprng_state->ctr_drbg, output_buffer, output_size, additional_input, csprng_state->additional_input_length_generate );
    if ( error ) {
      fprintf(stderr, "ERROR: nist_ctr_drbg_generate has returned %d\n",error);
      return(0);
    }

  } else {

    error = nist_ctr_drbg_generate( csprng_state->ctr_drbg, output_buffer, output_size, additional_input, csprng_state->additional_input_length_generate );
    if ( error ) {
      fprintf(stderr, "ERROR: nist_ctr_drbg_generate has returned %d\n",error);
      return(0);
    }
  }

  //fwrite (output_buffer, sizeof(unsigned char), 512*16, stdout);

  if ( reseed ) {
    if ( csprng_state->additional_input_length_generate ) {
      entropy = get_data_from_RNG_buffer ( csprng_state->entropy_buf, csprng_state->entropy_length );
      if ( entropy == NULL) return(0);
      //dump_hex_byte_string(entropy, csprng_state->entropy_length, "Reseed: \tentropy_input:     \t");
      csprng_state->entropy_tot += csprng_state->entropy_length;
      additional_input =  get_data_from_RNG_buffer ( csprng_state->add_input_buf, csprng_state->additional_input_length_reseed );
      if ( additional_input == NULL) return(0);
      //dump_hex_byte_string(additional_input, csprng_state->additional_input_length_reseed, "Reseed: \tadditional_input: \t");

      csprng_state->additional_input_reseed_tot += csprng_state->additional_input_length_reseed;
      error = nist_ctr_drbg_reseed(csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length_reseed );
      if ( error ) {
        fprintf(stderr, "ERROR: nist_ctr_drbg_reseed has returned %d\n",error);
        return(0);
      }
    } else {
      entropy = get_data_from_RNG_buffer ( csprng_state->entropy_buf, csprng_state->entropy_length );
      if ( entropy == NULL) return(0);
      //dump_hex_byte_string(entropy, csprng_state->entropy_length, "Reseed: \tentropy_input:     \t");
      csprng_state->entropy_tot += csprng_state->entropy_length;

      error = nist_ctr_drbg_reseed(csprng_state->ctr_drbg, entropy, csprng_state->entropy_length, additional_input, csprng_state->additional_input_length_reseed );
      if ( error ) {
        fprintf(stderr, "ERROR: nist_ctr_drbg_reseed has returned %d\n",error);
        return(0);
      }
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
  int return_value=0;   //0 => OK, 1 =>ERROR

  if ( csprng_state == NULL ) return 1;

  if ( csprng_state->ctr_drbg != NULL ) {
    if ( nist_ctr_drbg_destroy(csprng_state->ctr_drbg) != 0 ) {
      fprintf(stderr, "ERROR: nist_ctr_drbg_destroy has failed.\n");
      return_value = 1;
    }
  }

  if ( csprng_state->add_input_buf != NULL ) {
   destroy_buffer(csprng_state->add_input_buf);
  } 

  if ( csprng_state->random_length_buf != NULL ) {
    destroy_buffer(csprng_state->random_length_buf);
  }

  if ( csprng_state->entropy_buf !=NULL ) {
    destroy_buffer( csprng_state->entropy_buf );
  }

  if ( csprng_state->http != NULL ) {
    http_random_destroy( csprng_state->http );
  }

  if ( csprng_state->sha != NULL ) {
    destroy_SHA1( csprng_state->sha );
  }

  if (  csprng_state->memt != NULL ) {
    MEMT_destroy( csprng_state->memt );
  }

  if ( csprng_state->HAVEGE_initialized == 1 ) {
    havege_destroy();
  }

  //We will not close STDIN
  if ( csprng_state->mode.add_input_source == EXTERNAL && csprng_state->file_for_additional_buf != NULL ) {
    if ( fclose( csprng_state->file_for_additional_buf ) ) {
      return_value = 1;
      fprintf(stderr, "ERROR: cannot close file '%s'.  Reported error: %s\n", csprng_state->mode.filename_for_additional, strerror(errno));
    }
  }

  if ( csprng_state->mode.filename_for_additional != NULL ) {
    free (csprng_state->mode.filename_for_additional);
  }

  //We will not close STDIN
  if ( csprng_state->mode.entropy_source == EXTERNAL && csprng_state->file_for_entropy_buf != NULL ) {
    if ( csprng_state->are_files_same == 0 )  {
      if ( fclose ( csprng_state->file_for_entropy_buf ) ) {
        return_value = 1;
        fprintf(stderr, "ERROR: cannot close file '%s'.  Reported error: %s\n", csprng_state->mode.filename_for_entropy, strerror(errno));
      }
    } else {
      csprng_state->file_for_entropy_buf = csprng_state->file_for_additional_buf;
    }
  }

  if ( csprng_state->mode.filename_for_entropy != NULL ) {
    free ( csprng_state->mode.filename_for_entropy );
  }

  memset(csprng_state, 0, sizeof(csprng_state_type) );
  free(csprng_state);

  return return_value;
}		/* -----  end of function csprng_destroy  ----- */
//}}}

//{{{ fips_state_type* fips_approved_csprng_initialize(int perform_fips_test, int track_fips_CPU_time, const mode_of_operation_type* mode_of_operation)
// Init buffer between CSPRNG output and FIPS input
fips_state_type* fips_approved_csprng_initialize(int perform_fips_test, int track_fips_CPU_time, const mode_of_operation_type* mode_of_operation)
{
  unsigned int fips_continuos_test_seed;
  unsigned int size;
  rng_state_type rng_state;
  fips_state_type *fips_state;
  unsigned char* seed;
  char locked;                  //Was seed locked?
  unsigned int allocated_size;  //Number of bytes allocated for seed.

  fips_state = (fips_state_type*) calloc( 1, sizeof(fips_state_type));
  if ( fips_state == NULL ) {
    fprintf(stderr, "ERROR: Dynamic memory allocation has failed for fips_state_type variable"
       " of size %zu. Reported error: %s\n", sizeof(fips_state_type), strerror(errno));
    return NULL;
  }

  memset(&rng_state, 0, sizeof(rng_state) );
  fips_state->csprng_state = csprng_initialize(mode_of_operation);
  if ( fips_state->csprng_state == NULL ) {
    fprintf(stderr, "ERROR: csprng_initialize has failed.\n");
    goto fips_approved_csprng_initialize_clean;
  }

  if ( perform_fips_test ) {
    fips_state->perform_fips_test = 1;
    seed = create_seed("/dev/urandom", sizeof(fips_continuos_test_seed), &locked, &allocated_size);
    if ( seed == NULL ) goto fips_approved_csprng_initialize_clean;

    fips_continuos_test_seed = *((unsigned int*) (seed));
    destroy_seed(seed, &locked, &allocated_size);
    //fprintf(stderr, "fips_approved_csprng_initialize: seed %u\n", fips_continuos_test_seed);

    fips_state->max_bytes_to_get_from_raw_buf = FIPS_RNG_BUFFER_SIZE;
  } else {
    fips_state->perform_fips_test = 0;
    fips_continuos_test_seed = 0;
    fips_state->max_bytes_to_get_from_raw_buf = ( fips_state->csprng_state->mode.max_number_of_csprng_generated_bytes > NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) ?
      NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST : fips_state->csprng_state->mode.max_number_of_csprng_generated_bytes;
  }


  fips_init( &fips_state->fips_ctx, fips_continuos_test_seed, track_fips_CPU_time);
  //Max number of bytes to be put into fips_state->raw_buf
  size = ( fips_state->csprng_state->mode.max_number_of_csprng_generated_bytes > NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) ?
      ( unsigned int ) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST : fips_state->csprng_state->mode.max_number_of_csprng_generated_bytes;

  //Size of the fips_state->raw_buf
  size += fips_state->max_bytes_to_get_from_raw_buf;

  fips_state->raw_buf = init_buffer( NONE, rng_state, NULL, NULL, size, "FIPS TEST INPUT BUF");
  if ( fips_state->raw_buf == NULL ) {
    fprintf(stderr, "ERROR: init_buffer for fips_state->raw_buf has failed.\n");
    goto fips_approved_csprng_initialize_clean;
  }

  fips_state->out_buf = init_buffer( NONE, rng_state, NULL, NULL, fips_state->max_bytes_to_get_from_raw_buf, "FIPS TEST OUTPUT BUF");
  if ( fips_state->out_buf == NULL ) {
    fprintf(stderr, "ERROR: init_buffer for fips_state->out_buf has failed.\n");
    goto fips_approved_csprng_initialize_clean;
  }

  return fips_state;

fips_approved_csprng_initialize_clean:
  fips_approved_csprng_destroy(fips_state);
  return NULL;

} /* -----  end of function fips_approved_csprng_initialize  ----- */
//}}}

//{{{ int fips_approved_csprng_instantiate( fips_state_type* fips_state)
int fips_approved_csprng_instantiate( fips_state_type* fips_state) {
  int return_code;

  return_code = csprng_instantiate(fips_state->csprng_state);
  if ( return_code ) {
    fprintf(stderr, "ERROR: csprng_instantiate has failed.\n");
    fips_approved_csprng_destroy(fips_state);
    return 1;
  }
  
  return 0;
} /* -----  end of function fips_approved_csprng_instantiate  ----- */
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
        fprintf(stderr,"# stdin_input_raw(): ERROR: %s\n", strerror(errno));
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
int fips_approved_csprng_generate (fips_state_type *fips_state, unsigned char *output_buffer, unsigned int output_size)
{
  const unsigned char* raw_data;
  int fips_result=0;
  int bytes_to_put_into_buffer;
  int bytes_written=0;
  int remaining_bytes;
  int requested_bytes;

//Do we have some data in the buffer??
  if ( fips_state->out_buf->valid_data_size > 0 ) {
    if ( fips_state->out_buf->valid_data_size < output_size ) {
      memcpy(output_buffer, fips_state->out_buf->buf_start, fips_state->out_buf->valid_data_size);
      bytes_written += fips_state->out_buf->valid_data_size;
      output_buffer += fips_state->out_buf->valid_data_size;
      fips_state->out_buf->buf_start = fips_state->out_buf->buf;
      fips_state->out_buf->valid_data_size = 0;
    } else if ( fips_state->out_buf->valid_data_size == output_size) {
      memcpy(output_buffer, fips_state->out_buf->buf_start, output_size);
      fips_state->out_buf->buf_start = fips_state->out_buf->buf;
      fips_state->out_buf->valid_data_size = 0;
      //fprintf(stderr, "#fips_approved_csprng_generate: returned bytes %d, remaining bytes in the buffer %d\n", output_size, fips_state->out_buf.valid_data_size);
      return output_size;
    } else {
      memcpy(output_buffer, fips_state->out_buf->buf_start, output_size);
      fips_state->out_buf->buf_start += output_size;
      fips_state->out_buf->valid_data_size -= output_size;
      //fprintf(stderr, "#fips_approved_csprng_generate: returned bytes %d, remaining bytes in the buffer %d\n", output_size, fips_state->out_buf.valid_data_size);
      return output_size;
    }
  }

  remaining_bytes = output_size - bytes_written;
  while ( (unsigned int) ( bytes_written ) < output_size ) {

    if ( fips_state->perform_fips_test ) {
      requested_bytes = FIPS_RNG_BUFFER_SIZE;
      raw_data = get_data_from_csprng_buffer(fips_state, requested_bytes);
      //raw_data = get_data_from_stdin_buffer(fips_state, requested_bytes);
      if ( raw_data == NULL) {
        //fprintf(stderr, "#fips_approved_csprng_generate: returned bytes %d, remaining bytes in the buffer %d\n", bytes_written, fips_state->out_buf.valid_data_size);
        return(bytes_written);
      }
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
      if ( raw_data == NULL) {
        //fprintf(stderr, "#fips_approved_csprng_generate: returned bytes %d, remaining bytes in the buffer %d\n", bytes_written, fips_state->out_buf.valid_data_size);
        return(bytes_written);
      }
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
        assert(fips_state->out_buf->valid_data_size == 0);
        assert( ( int ) fips_state->out_buf->total_size - ( int ) fips_state->out_buf->valid_data_size >= bytes_to_put_into_buffer);
        memcpy(fips_state->out_buf->buf_start + fips_state->out_buf->valid_data_size, raw_data, bytes_to_put_into_buffer);
        fips_state->out_buf->valid_data_size += bytes_to_put_into_buffer;
  
        //fprintf(stderr, "#fips_approved_csprng_generate: returned bytes %d, remaining bytes in the buffer %d\n", output_size, fips_state->out_buf.valid_data_size);
        return output_size;
      }
    }
  }
  //fprintf(stderr, "#fips_approved_csprng_generate: returned bytes %d, remaining bytes in the buffer %d\n", output_size, fips_state->out_buf.valid_data_size);
  return output_size;
} /* -----  end of function fips_approved_csprng_generate  ----- */
//}}}

//{{{ int fips_approved_csprng_destroy (fips_state_type *fips_state)
int fips_approved_csprng_destroy (fips_state_type *fips_state) 
{
  int return_value=0;   //o = OK, 1 =ERROR

  if ( fips_state == NULL ) return 1;

  //if ( fips_state->perform_fips_test ) {
  //  fprintf(stderr, "%s", dump_fips_statistics( &fips_state->fips_ctx.fips_statistics ) );
  //}


  if ( fips_state->out_buf != NULL ) {
    destroy_buffer( fips_state->out_buf);
  }

  if ( fips_state->raw_buf != NULL ) {
    destroy_buffer( fips_state->raw_buf);
  }

  memset(&fips_state->fips_ctx, 0, sizeof(fips_ctx_t) );

  if ( fips_state->csprng_state != NULL ) {
    if ( csprng_destroy( fips_state->csprng_state) != 0 ) {
      fprintf(stderr, "ERROR: csprng_destroy has failed.\n");
      return_value = 1;
    }
  }
  
  memset(fips_state, 0, sizeof(fips_state_type));
  free(fips_state);
  return return_value;

}
//}}}  

//{{{ int fips_approved_csprng_statistics (fips_state_type *fips_state)
////TODO
int fips_approved_csprng_statistics (fips_state_type *fips_state) 
{
  int return_value=0;   //o = OK, 1 =ERROR

  if ( fips_state == NULL ) return 1;

  fprintf(stderr,"Entropy buffer: total bytes generated %20"PRIu64", total bytes sent out %20"PRIu64"\n", 
      fips_state->csprng_state->entropy_buf->bytes_in, fips_state->csprng_state->entropy_buf->bytes_out);

  fprintf(stderr,"csprng_generate: total bytes of entropy used to reseed CSRNG %20"PRIu64"\n", 
      fips_state->csprng_state->entropy_tot);


   if ( fips_state->csprng_state->additional_input_length_generate ) {
     fprintf(stderr,"Additional input buffer: total bytes generated %20"PRIu64", total bytes sent out %20"PRIu64"\n", 
         fips_state->csprng_state->add_input_buf->bytes_in, fips_state->csprng_state->add_input_buf->bytes_out);
     fprintf(stderr,"csprng_generate: total bytes of additional input used to reseed CSRNG %20"PRIu64"\n", 
         fips_state->csprng_state->additional_input_reseed_tot);
     fprintf(stderr,"csprng_generate: total bytes of additional input used for generate process of CSRNG %20"PRIu64"\n", 
         fips_state->csprng_state->additional_input_generate_tot);
     fprintf(stderr,"csprng_generate: Grand total of additional input used %20"PRIu64" Bytes.\n", 
         fips_state->csprng_state->additional_input_reseed_tot + fips_state->csprng_state->additional_input_generate_tot);

   }

  return return_value;

}
//}}}  

//{{{ void csprng_estimate_bytes_needed ( csprng_state_type* csprng_state, char unlimited, uint64_t size, uint64_t output_buffer_size,
//                                        char verbose, long double http_reasonable_length, long double target_rate, long double http_rng_rate )
//This function will estimate the number of ENTROPY and ADDITIONAL_INPUT BYTES needed to generate 
//size BYTES
//size + output_buffer_size BYTES
//For unlimited output it will compute just rates and ratios
//For HTTP_RNG with input rate "http_rng_rate" it will compute output_rate and compare it against "target_rate"
//The above check will happen only when HTTP bytes needed > http_reasonable_length
//verbose => verbosity level. 0=>quit, 2=> maximal verbosity
void csprng_estimate_bytes_needed ( csprng_state_type* csprng_state, char unlimited, uint64_t size, uint64_t output_buffer_size,
    char verbose, long double http_reasonable_length, long double http_rng_rate, long double target_rate ) {

  //{{{ Estimate the needed size of entropy and additional_input sources
  const uint64_t entropy_length = csprng_state->entropy_length;
  const uint64_t ai_reseed = ( csprng_state->mode.add_input_source != NONE ) ? csprng_state->additional_input_length_reseed : 0;
  const uint64_t ai_generate = ( csprng_state->mode.add_input_source != NONE ) ? csprng_state->additional_input_length_generate : 0;
  const long double average_output_length = ( csprng_state->mode.random_length_of_csprng_generated_bytes ) ? 
    csprng_state->mode.max_number_of_csprng_blocks * NIST_BLOCK_OUTLEN_BYTES * 0.5L :
    csprng_state->mode.max_number_of_csprng_blocks * NIST_BLOCK_OUTLEN_BYTES ;
  long double generate_to_reseed_ratio;
  uint64_t http_rng_entropy_bytes_needed = 0;
  uint64_t http_rng_ai_bytes_needed = 0;

  if ( csprng_state->mode.max_number_of_csprng_blocks * (uint64_t) NIST_BLOCK_OUTLEN_BYTES <= (uint64_t) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) {
    generate_to_reseed_ratio = 1.0L;
  } else if ( csprng_state->mode.random_length_of_csprng_generated_bytes ) {
    long double max_bytes =  (long double) csprng_state->mode.max_number_of_csprng_blocks * (long double) NIST_BLOCK_OUTLEN_BYTES;
    long double full_intervals = floorl ( max_bytes / (long double) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST );

    //Number of generate calls for one reseed call:
    //Number of interval * p (of interval)
    //Sum over all full intervals: p*1 + p*2 + p*3 + .. = p * (N+1) * N / 2
    generate_to_reseed_ratio = (long double) ( NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) / max_bytes *
      ( full_intervals + 1.0L ) * full_intervals / 2.0L;
    //Last interval is not full 
    generate_to_reseed_ratio += ( max_bytes - full_intervals * (long double) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) / max_bytes *
      ( full_intervals + 1.0L );
  } else {
    generate_to_reseed_ratio = ceill( average_output_length / (long double) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST );
  }

  const uint64_t ai_length = ai_reseed + ceill ( ai_generate * generate_to_reseed_ratio );
  const uint64_t total_input_length = entropy_length + ai_length;

  if ( verbose > 1 ) {
    fprintf (stderr, "%-80s%-5"PRIu64"%s\n", "Entropy needed to reseed CSPRNG: ", entropy_length, " Bytes");

    if ( csprng_state->mode.add_input_source != NONE ) {
      fprintf (stderr, "%-80s%-5"PRIu64"%s\n", "Additional input needed to reseed CSPRNG: ", ai_reseed, " Bytes");
      fprintf (stderr, "%-80s%-5"PRIu64"%s\n", "Additional input needed to start the generate process (back-trace resistance): ",
          ai_generate, " Bytes");
      if ( csprng_state->mode.random_length_of_csprng_generated_bytes ) 
        fprintf (stderr, "%-80s%-5Lg\n", "Average number of generate calls executed before next reseed operation: ",
            generate_to_reseed_ratio);
      else 
        fprintf (stderr, "%-80s%-5Lg\n", "Number of generate calls executed before next reseed operation: ",
            generate_to_reseed_ratio);

      fprintf( stderr, "%-80s%-5"PRIu64"%s\n", "Total additional input length to reseed CSPRNG and execute all generate calls: ",
          ai_length, " Bytes" );
    }


    if ( csprng_state->mode.random_length_of_csprng_generated_bytes ) {
      fprintf (stderr, "%-80s%s%s%.0Lf%s\n", "Average length of random bytes produced between reseeds of CSPRNG: ",
          human_print_ldouble_left_alligned (average_output_length), "ytes, (", average_output_length, " Bytes)");
    } else {
      fprintf (stderr, "%-80s%s%s%.0Lf%s\n", "Total length of random bytes produced between reseeds of CSPRNG: ",
          human_print_ldouble_left_alligned (average_output_length), "ytes, (", average_output_length, " Bytes)");
    }

    fprintf (stderr, "%-80s%-5Lg\n", "Output length / entropy length  = ",
        average_output_length / (long double) entropy_length );

    if ( csprng_state->mode.add_input_source != NONE ) {
      fprintf (stderr, "%-80s%-5Lg\n","Output length / additional input length = ",
          average_output_length / (long double) ai_length );
      fprintf (stderr, "%-80s%-5Lg\n", "Output length / Total input length  = ",
          average_output_length / (long double) total_input_length );
    }
  }

  if ( ! unlimited ) {
    int i;
    for ( i=0; i<2; ++i ) {
      //i == 0 => without OUTPUT buffers
      //i == 1 => with OUTPUT buffers
      uint64_t total_bytes_to_generate;
      if ( verbose > 1 ) fprintf ( stderr, "\n***************************************************************************************************\n");
      if ( i == 0 ) {
        total_bytes_to_generate = size;
        if ( verbose > 1 ) fprintf ( stderr, "ESTIMATED NUMBER OF OPERATIONS TO GENERATE %"PRIu64" BYTES WITHOUT OUTPUT BUFFER\n", total_bytes_to_generate);
      } else {
        total_bytes_to_generate = size + output_buffer_size;
        if ( verbose > 1 ) fprintf ( stderr, "ESTIMATED NUMBER OF OPERATIONS TO GENERATE %"PRIu64" BYTES INCLUDING OUTPUT BUFFER OF SIZE %"PRIu64" BYTES\n",
            total_bytes_to_generate, output_buffer_size);
      }


      uint64_t reseed_op   = ceill( (long double) (total_bytes_to_generate) / average_output_length);
      uint64_t generate_op = floorl(reseed_op * generate_to_reseed_ratio);
      long double bytes_in_last_generate_call =  (long double) (total_bytes_to_generate) - average_output_length * floorl( (long double) (total_bytes_to_generate) / average_output_length  );
      //fprintf(stderr, "bytes_in_last_generate_call %.0Lf\n", bytes_in_last_generate_call);
      generate_op += ceill( bytes_in_last_generate_call / (long double) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST );
      reseed_op += 1; //Instantiate will call reseed operation
      uint64_t entropy_res_tot = reseed_op * entropy_length;
      uint64_t entropy_tot = entropy_res_tot + entropy_length;
      uint64_t ai_res_tot  = reseed_op * ai_reseed;
      uint64_t ai_gen_tot  = generate_op * ai_generate;
      uint64_t ai_tot      = ai_res_tot + ai_gen_tot + ai_reseed;
      uint64_t en_buf_size = csprng_state->entropy_buf->total_size;
      uint64_t ai_buf_size = ( csprng_state->mode.add_input_source != NONE ) ? csprng_state->add_input_buf->total_size : 0;


      if ( verbose > 1 ) {
        fprintf ( stderr, "***************************************************************************************************\n");
        fprintf ( stderr, "OPERATION    # OF OPERATIONS EXPECTED        ENTROPY BYTES    ADDITIONAL INPUT BYTES\n");
        fprintf ( stderr, "%-14s%23"PRIu64"%20"PRIu64"%25"PRIu64"\n", "Instantiate", (uint64_t) 1, entropy_length, ai_reseed);
        fprintf ( stderr, "%-14s%23"PRIu64"%20"PRIu64"%25"PRIu64"\n", "Reseed", reseed_op, entropy_res_tot, ai_res_tot);
        fprintf ( stderr, "%-14s%23"PRIu64"%20"PRIu64"%25"PRIu64"\n", "Generate", generate_op, (uint64_t) 0, ai_gen_tot);
        fprintf ( stderr, "%-37s%20"PRIu64"%25"PRIu64"\n", "TOTAL", entropy_tot, ai_tot);
        fprintf ( stderr, "%-37s%20"PRIu64"%25"PRIu64"\n", "INPUT BUFFER SIZE", en_buf_size, ai_buf_size);
        fprintf ( stderr, "%-37s%20"PRIu64"%25"PRIu64"\n", "INCLUDING INPUT BUFFER SIZE", en_buf_size+entropy_tot, ai_buf_size+ai_tot);
        fprintf ( stderr, "***************************************************************************************************\n");
      }

      if ( i == 0 ) {
        if ( csprng_state->mode.entropy_source == HTTP_RNG )   http_rng_entropy_bytes_needed = entropy_tot;
        if ( csprng_state->mode.add_input_source == HTTP_RNG ) http_rng_ai_bytes_needed      = ai_gen_tot;
      }
    }
  }
  //}}}

  //{{{ For HTTP_RNG estimate the output rate based on HTTP input rate
  if ( csprng_state->mode.entropy_source == HTTP_RNG || csprng_state->mode.add_input_source == HTTP_RNG ) {

    if ( http_rng_entropy_bytes_needed +  http_rng_ai_bytes_needed > http_reasonable_length ||  unlimited ) {
      long double output_rate;
      uint64_t suggested_max_num_of_blocks_based_on_rate;
      uint64_t suggested_max_num_of_blocks_based_on_input_length = 0.0L;

      uint64_t step_for_num_of_blocks = ( (uint64_t) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) / ( (uint64_t) NIST_BLOCK_OUTLEN_BYTES );

      //{{{ HTTP_RNG is used only for the entropy input - recommended way of operation
      if ( csprng_state->mode.entropy_source == HTTP_RNG && csprng_state->mode.add_input_source != HTTP_RNG ) {
        output_rate =  average_output_length / (long double) (entropy_length) * http_rng_rate;
        if ( output_rate < target_rate ) {
          fprintf(stderr, "WARNING: Assuming that HTTP input rate for entropy is %s/s ", human_print_ldouble(http_rng_rate));
          fprintf(stderr, "the output rate will be %s/s ",  human_print_ldouble(output_rate));
          fprintf(stderr, "which is bellow expected CPU-bound rate of %s/s\n\n", human_print_ldouble(target_rate));
          if ( csprng_state->mode.random_length_of_csprng_generated_bytes ) {
            suggested_max_num_of_blocks_based_on_rate = ceill ( 2.0L * target_rate / http_rng_rate * (long double) entropy_length / (long double) NIST_BLOCK_OUTLEN_BYTES ) ;
          } else {
            suggested_max_num_of_blocks_based_on_rate = ceill (        target_rate / http_rng_rate * (long double) entropy_length / (long double) NIST_BLOCK_OUTLEN_BYTES ) ;
          }

          //Round suggested_max_num_of_blocks_based_on_rate to be multiple of step_for_num_of_blocks
          if ( suggested_max_num_of_blocks_based_on_rate % step_for_num_of_blocks ) 
            suggested_max_num_of_blocks_based_on_rate += step_for_num_of_blocks - suggested_max_num_of_blocks_based_on_rate % step_for_num_of_blocks;


          if ( ! unlimited ) {
            if ( csprng_state->mode.random_length_of_csprng_generated_bytes ) {
              suggested_max_num_of_blocks_based_on_input_length = ceill ( 2.0L * (long double) (size) * (long double) entropy_length / 
                  ( (long double) NIST_BLOCK_OUTLEN_BYTES  * http_reasonable_length ) );
            } else {
              suggested_max_num_of_blocks_based_on_input_length = ceill (        (long double) (size) * (long double) entropy_length / 
                  ( (long double) NIST_BLOCK_OUTLEN_BYTES  * http_reasonable_length ) );
            }

            //Round suggested_max_num_of_blocks_based_on_input_length to be multiple of step_for_num_of_blocks
            if ( suggested_max_num_of_blocks_based_on_input_length % step_for_num_of_blocks ) 
              suggested_max_num_of_blocks_based_on_input_length += step_for_num_of_blocks - suggested_max_num_of_blocks_based_on_input_length % step_for_num_of_blocks;

            //fprintf(stderr, "suggested_max_num_of_blocks_based_on_input_length %"PRIu64"\n", suggested_max_num_of_blocks_based_on_input_length);
          }


          if ( ! unlimited && ( suggested_max_num_of_blocks_based_on_input_length < suggested_max_num_of_blocks_based_on_rate ) ) {
            fprintf(stderr, "WARNING: To reduce entropy input length to approximatelly %s,  --max_num_of_blocks=%"PRIu64" is recommended.\n",
                human_print_ldouble(http_reasonable_length), suggested_max_num_of_blocks_based_on_input_length);
          } else {
            fprintf(stderr, "WARNING: To achieve output rate of %s/s,  --max_num_of_blocks=%"PRIu64" is recommended.\n",
                human_print_ldouble(target_rate), suggested_max_num_of_blocks_based_on_rate);
          }
        }
      }
      //}}}

      //{{{ HTTP_RNG is used only as additional input - not recommended
      if ( csprng_state->mode.add_input_source == HTTP_RNG && csprng_state->mode.entropy_source != HTTP_RNG ) {
        output_rate =  average_output_length / (long double) (ai_length) * http_rng_rate;
        if ( output_rate < target_rate ) {
          fprintf(stderr, "WARNING: Assuming that HTTP input rate for additional input is %.0Lf the output rate will be %.0Lf which is bellow expected CPU-bound rate of %.0Lf\n",
              http_rng_rate, output_rate, target_rate);
          fprintf(stderr, "WARNING: It's not recommended to use HTTP_RNG as additional input source as even with the very large --max_num_of_blocks parameter output rate of maximum %.0Lf can be achieved.\n",
              http_rng_rate  * (long double) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST / (long double) ( ai_generate ) );
        }
      }
      //}}}

      //{{{ HTTP_RNG is sued for both entropy and additional_input - not recommended
      if ( csprng_state->mode.entropy_source == HTTP_RNG && csprng_state->mode.add_input_source == HTTP_RNG ) {
        output_rate =  average_output_length / (long double) (total_input_length) * http_rng_rate;
        if ( output_rate < target_rate ) {
          fprintf(stderr, "WARNING: Assuming that HTTP input rate for entropy and additional input is %.0Lf the output rate will be %.0Lf which is bellow expected CPU-bound rate of %.0Lf\n",
              http_rng_rate, output_rate, target_rate);
          fprintf(stderr, "WARNING: It's not recommended to use HTTP_RNG as additional input source as even with the very large --max_num_of_blocks parameter output rate of maximal %.0Lf can be achieved.\n",
              http_rng_rate  * (long double) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST / (long double) ( ai_generate ) );
        }
      }
      //}}}

    }
  }
}
//}}}
