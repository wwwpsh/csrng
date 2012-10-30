/*
gcc -I../include -Wall -g -O2 -c -o TestU01.o TestU01.c
gcc -Wall -g -O2  -L ../src/.libs -o TestU01 TestU01.o -lcsprng -lssl -ltestu01
env -i LD_LIBRARY_PATH=$(readlink -f ../src/.libs) TestU01 -s
\time env -i LD_LIBRARY_PATH=$(readlink -f ../src/.libs) MALLOC_CHECK_=1 ./TestU01 -n

Compile with -lmcheck
gcc -Wall -g -O2  -L ../src/.libs -o TestU01 TestU01.o -lcsprng -lssl -ltestu01 -lmcheck

gcc -Wall -g -O2  -L ../src/.libs -o TestU01 TestU01.o -lcsprng -lssl -ltestu01 -Wl,rpath=$(readlink -f ../src/.libs)
gcc -Wall -g -O2  -o TestU01 ../src/libcsprng_la-havege.o ../src/libcsprng_la-nist_ctr_drbg_mod.o ../src/libcsprng_la-csprng.o TestU01.o  -lssl -ltestu01
gcc -Wall -g -O2  -o TestU01 ../src/havege.o ../src/nist_ctr_drbg_mod.o ../src/csprng.o TestU01.o  -lssl -ltestu01

32-bit

gcc -m32 -I../src -Wall -g -O2 -c -o TestU01.o TestU01.c
gcc -m32 -Wall -g -O2  -o TestU01 ../src/havege.o ../src/nist_ctr_drbg_mod.o ../src/csprng.o TestU01.o /home/jirka/C/64-bit/2011-Nov-19-TestU01/TestU01-1.2.3/./testu01/.libs/libtestu01.so -lssl

LD_LIBRARY_PATH=/home/jirka/C/64-bit/2011-Nov-19-TestU01/TestU01-1.2.3/./testu01/.libs /home/jirka/C/64-bit/2011-Nov-21-Ermine/ErmineLightTrial.i386 -v -K --ld_assume_kernel=2.6.15 TestU01 --output=TestU01_AllCrush_32
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>

#include <unif01.h>
#include <bbattery.h>

#include "csprng/csprng.h"


typedef struct {
  rng_buf_type output_buf;                     //Output Buffer
  fips_state_type   fips_state;                //Generator state
  mode_of_operation_type mode_of_operation;    //Mode of operation
  int size ;                                   //Maximum number of bytes produced during one step
} csprng_output_type;


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_init_buf
 *  Description:  
 * =====================================================================================
 */
int
csprng_init_out ( csprng_output_type* data, int size )
{
  int error;
  int fips_test = 0;
  int max_num_of_blocks = 512;
  int randomize_num_of_blocks = 0;
  
  data->size = size; 
  error = fips_approved_csprng_init(&data->fips_state, fips_test, 
      max_num_of_blocks, randomize_num_of_blocks, 0,
      &data->mode_of_operation);

  if ( error ) {
    fprintf(stderr, "Error: fips_approved_csprng_init has returned %d\n",error);
    return(error);
  }


  data->output_buf.buf	= (unsigned char*) malloc ( size + sizeof(unsigned int) );
  if (  data->output_buf.buf==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  }
  data->output_buf.total_size = size + sizeof(unsigned int);
  data->output_buf.valid_data_size = 0;
  data->output_buf.buf_start = data->output_buf.buf;
  return 0;
}		/* -----  end of function csprng_init_buf  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_destroy_buf
 *  Description:  
 * =====================================================================================
 */
int
csprng_destroy_out ( csprng_output_type* data )
{
  int return_code;

  free (data->output_buf.buf);
  data->output_buf.buf	= NULL;
  data->output_buf.buf_start = NULL;
  data->output_buf.total_size = 0;
  data->output_buf.valid_data_size = 0;

  return_code = fips_approved_csprng_destroy(&data->fips_state);
  if ( return_code ) {
    error(EXIT_FAILURE, errno, "ERROR: fips_approved_csprng_destroy has returned %d\n",return_code);
  }
  return 0;

}		/* -----  end of function csprng_destroy_buf  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_fill_buf
 *  Description:  
 * =====================================================================================
 */
int
csprng_fill_out ( csprng_output_type* data )
{
  int bytes_generated;

  // 1. Rewind buffer
  if ( data->output_buf.valid_data_size ) {
    memmove(data->output_buf.buf, data->output_buf.buf_start, data->output_buf.valid_data_size);
  }
  data->output_buf.buf_start =  data->output_buf.buf;

  // 2. Fill buffer
  while ( data->output_buf.valid_data_size + data->size <= data->output_buf.total_size ) {
    //memcpy(data->output_buf.buf_start + data->output_buf.valid_data_size, output, data->size);
    bytes_generated = fips_approved_csprng_generate(&data->fips_state, data->output_buf.buf_start + data->output_buf.valid_data_size, data->size);
    if ( bytes_generated < data->size ) {
      fprintf( stderr, "ERROR: fips_approved_csprng_generate has returned %d Bytes instead of %d Bytes requested.\n", 
          bytes_generated, data->size);
      return(EXIT_FAILURE);
    }
    data->output_buf.valid_data_size += data->size;
  }
  return 0;
}		/* -----  end of function csprng_fill_buf  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  csprng_get_unsigned_int_buf
 *  Description:  
 * =====================================================================================
 */
unsigned int
csprng_get_unsigned_int ( csprng_output_type* data )
{
  unsigned char* temp;
  const static unsigned int bytes_needed=4;   //TestU01 requires exactly 32bits
  unsigned int result;

  if ( bytes_needed > data->output_buf.valid_data_size ) {
    csprng_fill_out (data);
    if ( bytes_needed > data->output_buf.valid_data_size ) {
      fprintf ( stderr, "\nBuffer does not support such big data sizes\n" );
      exit (EXIT_FAILURE);
    }
  }

  data->output_buf.valid_data_size -= bytes_needed;
  temp = data->output_buf.buf_start;
  data->output_buf.buf_start = data->output_buf.buf_start + bytes_needed;

  result = ((unsigned int) (*temp) ) << 24;
  temp += 1;
  result |= ((unsigned int) (*temp) ) << 16;
  temp += 1;
  result |= ((unsigned int) (*temp) ) << 8;
  temp += 1;
  result |= ((unsigned int) (*temp) );

  //dump_hex_byte_string (temp-3, sizeof(unsigned int), "Big endian number:\t");
  //dump_hex_byte_string ((unsigned char *)&result, sizeof(unsigned int), "32-bit integer:\t");

  return(result);

}		/* -----  end of function csprng_get_unsigned_int_buf  ----- */


static csprng_output_type internal_status;

unsigned int csprng_get_unsigned_int_void ( ) {
  return csprng_get_unsigned_int(&internal_status);
}

int main (int argc, char **argv) 
{
   int sflag = 0;
   int nflag = 0;
   int bflag = 0;
   int c;

   opterr = 0;

   while ((c = getopt (argc, argv, "snb")) != -1)
     switch (c)
       {
       case 'b':
         bflag = 1;
         break;
       case 's':
         sflag = 1;
         break;
       case 'n':
         nflag = 1;
         break;
       case '?':
         if (isprint (optopt))
           fprintf (stderr, "Unknown option `-%c'.\n", optopt);
         else
           fprintf (stderr,
                    "Unknown option character `\\x%x'.\n",
                    optopt);
         return 1;
       default:
         abort ();
       }


  unif01_Gen *gen;

  internal_status.mode_of_operation.use_df                        = 0;
  internal_status.mode_of_operation.use_additional_input          = 0;
  internal_status.mode_of_operation.havege_debug_flags            = 0;
  internal_status.mode_of_operation.havege_status_flag            = 0;           
  internal_status.mode_of_operation.havege_data_cache_size        = 0;        
  internal_status.mode_of_operation.havege_instruction_cache_size = 0; 

  csprng_init_out (&internal_status, 512*16);

  gen = unif01_CreateExternGenBits ("Havege with CTR_DRBG", csprng_get_unsigned_int_void);

  if (sflag) bbattery_SmallCrush (gen);
  if (nflag) bbattery_Crush (gen);
  if (bflag) bbattery_BigCrush (gen);

  unif01_DeleteExternGenBits (gen);

  csprng_destroy_out (&internal_status);


  return 0;
}

