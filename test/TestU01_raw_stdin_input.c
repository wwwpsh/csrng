/*
gcc -Wall -g -O2 -c -o TestU01_raw_stdin_input.o TestU01_raw_stdin_input.c
gcc -Wall -g -O2  -o TestU01_raw_stdin_input TestU01_raw_stdin_input.o -ltestu01

../utils/csprng-generate -n 2757167464 | tee >(md5sum 1>&2) | TestU01_raw_stdin_input -f | md5sum


../utils/csprng-generate | throttle -M 2 | pv  | TestU01_raw_stdin_input_7 -r -t

*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unif01.h>
#include <bbattery.h>
#include <arpa/inet.h>

#define HANDLE_ENDIANES
//Assuming that input is in BIG ENDIAN byte order

typedef struct {
  unsigned char* buf;       //Buffer to pass values
  int total_size;           //Total size of buffer
  unsigned char* buf_start; //Start of valid data
  int valid_data_size;      //Size of valid data
  int read_size;            //How many bytes are attemted to be read during one fread call
  int eof_detected;         //EOF has been detected
} rng_buf_type;

void
dump_hex_byte_string (const unsigned char* data, const unsigned int size, const char* message) {
  unsigned int i;
  if (message)
	  fprintf(stderr,"%s",message);

  for (i=0; i<size; ++i) {
	fprintf(stderr,"%02x",data[i]);
  }
  fprintf(stderr,"\n");
}


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_buf
 *  Description:  
 * =====================================================================================
 */
int
init_buf ( rng_buf_type* data, int read_size )
{
  data->read_size = read_size;
  data->buf	= (unsigned char*) malloc ( read_size + sizeof(unsigned int) );
  if (  data->buf==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  }
  data->total_size = read_size + sizeof(unsigned int);
  data->valid_data_size = 0;
  data->buf_start = data->buf;
  data->eof_detected = 0;
  return 0;
}		/* -----  end of function init_buf  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  destroy_buf
 *  Description:  
 * =====================================================================================
 */
int
destroy_buf ( rng_buf_type* data )
{
  free (data->buf);
  data->buf	= NULL;
  data->buf_start = NULL;
  data->total_size = 0;
  data->valid_data_size = 0;
  data->read_size = 0;
  return 0;
}		/* -----  end of function destroy_buf  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  fill_buf
 *  Description:  
 * =====================================================================================
 */
int
fill_buf ( rng_buf_type* data, int min_length_of_valid_data )
{
  int bytes_read;
  int bytes_requested;
  int bytes_to_fill_the_buffer;
  assert(min_length_of_valid_data <= data->total_size);
  if ( data->eof_detected ) {
    if ( data->valid_data_size < min_length_of_valid_data ) {
      return(1);
    } else {
      return(0);
    }
  }

  // 1. Rewind buffer
  if ( data->valid_data_size ) {
    memmove(data->buf, data->buf_start, data->valid_data_size);
  }
  data->buf_start =  data->buf;

  // 2. Fill buffer
  while ( data->valid_data_size < min_length_of_valid_data ) {
    bytes_to_fill_the_buffer = data->total_size - data->valid_data_size;
    //Minimum of data->read_size and bytes_to_fill_the_buffer
    bytes_requested = data->read_size < bytes_to_fill_the_buffer ? data->read_size : bytes_to_fill_the_buffer;
    //memcpy(data->buf_start + data->valid_data_size, output, bytes_requested);
    bytes_read = fread(data->buf_start + data->valid_data_size, 1, bytes_requested, stdin);
    if ( bytes_read == 0 ) {
      if (feof(stdin)) {
        fprintf(stderr,"# stdin_input_raw(): EOF detected\n");
        data->eof_detected = 1;
      } else {
        fprintf(stderr,"# stdin_input_raw(): Error: %s\n", strerror(errno));
      }
      if ( data->valid_data_size < min_length_of_valid_data ) {
        return(1);
      } else {
        return(0);
      }
    }
    data->valid_data_size += bytes_read;
  }
  return 0;
}		/* -----  end of function csprng_fill_buf  ----- */


/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  get_unsigned_int_buf
 *  Description:  
 * =====================================================================================
 */
unsigned int
get_unsigned_int_buf ( rng_buf_type* data )
{
  unsigned char* temp;
  const static unsigned int bytes_needed=4;   //TestU01 requires exactly 32bits
  unsigned int result;

  if (  bytes_needed > data->total_size ) {
    fprintf ( stderr, "\nBuffer does not support such big data sizes\n" );
    fprintf ( stderr, "\nBytes requested: %u, buffer size: %u\n", bytes_needed, data->total_size);
    exit (EXIT_FAILURE);
  }

  if ( bytes_needed > data->valid_data_size ) {
    fill_buf (data, data->read_size > bytes_needed ? data->read_size : bytes_needed );
    if ( bytes_needed > data->valid_data_size ) {
      fprintf ( stderr, "\nRequested to fill the buffer has failed.\n" );
      fprintf ( stderr, "Bytes requested: %u, bytes available: %u\n", bytes_needed, data->valid_data_size);
      exit (EXIT_FAILURE);
    }
  }

  data->valid_data_size -= bytes_needed;
  temp = data->buf_start;
  data->buf_start += bytes_needed;

#ifdef HANDLE_ENDIANES
  result = ((unsigned int) (*temp) ) << 24;
  temp += 1;
  result |= ((unsigned int) (*temp) ) << 16;
  temp += 1;
  result |= ((unsigned int) (*temp) ) << 8;
  temp += 1;
  result |= ((unsigned int) (*temp) );
#else
  result = *((unsigned int*) temp );
#endif

  //dump_hex_byte_string (temp-3, sizeof(unsigned int), "Big endian number:\t");
  //dump_hex_byte_string ((unsigned char *)&result, sizeof(unsigned int), "32-bit integer:\t");

  return(result);

}		/* -----  end of function get_unsigned_int_buf  ----- */


static rng_buf_type internal_status;

unsigned int get_unsigned_int_void ( ) {
  return get_unsigned_int_buf(&internal_status);
}

int main (int argc, char **argv) 
{
   int sflag = 0;
   int nflag = 0;
   int bflag = 0;
   int rflag = 0;
   int fflag = 0;
   int tflag = 0;
   int c;
   int rep[97];
   int i;
   unsigned int data;
#ifdef HANDLE_ENDIANES
   unsigned int data_big_endian;
#endif

   for(i=0;i<97;++i) {
     rep[i] = 0;
   }

   rep[3]=10;
   rep[4]=10;

   opterr = 0;

   while ((c = getopt (argc, argv, "snbrft")) != -1)
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
       case 'r':
         rflag = 1;
         break;
       case 'f':
         fflag = 1;
         break;
        case 't':
         tflag = 1;
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
  init_buf (&internal_status, 512*16);
  
  if (fflag) {
    while(1) {
      data = get_unsigned_int_void();
#ifdef HANDLE_ENDIANES      
      data_big_endian = htonl(data);
      fwrite(&data_big_endian, 4, 1, stdout);
#else
      fwrite(&data, 4, 1, stdout);
#endif
    }
    return 0;
  }

  gen = unif01_CreateExternGenBits ("Raw STDIN input", get_unsigned_int_void);
  if (tflag) unif01_TimerSumGenWr (gen, 10000000, TRUE);

  if (rflag) bbattery_RepeatCrush (gen, rep);


  if (sflag) bbattery_SmallCrush (gen);
  if (nflag) bbattery_Crush (gen);
  if (bflag) bbattery_BigCrush (gen);

  unif01_DeleteExternGenBits (gen);

  destroy_buf (&internal_status);


  return 0;
}

