/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -Wall -Wextra -g -O2 -c -o TestU01_raw_stdin_input.o TestU01_raw_stdin_input.c
gcc -Wall -Wextra -g -O2  -o TestU01_raw_stdin_input TestU01_raw_stdin_input.o -ltestu01

../utils/csprng-generate -n 2757167464 | tee >(md5sum 1>&2) | TestU01_raw_stdin_input -f | md5sum


../utils/csprng-generate | throttle -M 2 | pv  | TestU01_raw_stdin_input_7 -r -t

*/

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


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <error.h>
#include <argp.h>
#include <limits.h>

#include <unif01.h>
#include <bbattery.h>
#include <arpa/inet.h>

#define HANDLE_ENDIANES
//Assuming that input is in BIG ENDIAN byte order

#define NUMBER_OF_SMALL_CRUSH_TESTS 11
#define NUMBER_OF_CRUSH_TESTS 97
#define NUMBER_OF_BIG_CRUSH_TESTS 107

typedef struct {
  unsigned char* buf;                //Buffer to pass values
  unsigned int total_size;           //Total size of buffer
  unsigned char* buf_start;          //Start of valid data
  unsigned int valid_data_size;      //Size of valid data
  unsigned int read_size;            //How many bytes are attemted to be read during one fread call
  int eof_detected;                  //EOF has been detected
} rng_buf_type;

typedef struct {
  unsigned long long number_of_32_bits;
  unsigned long long number_of_bytes_written_to_file;
} output_sta_type;

typedef struct {
  rng_buf_type rng_buf;
  output_sta_type output_sta;
} STDIN_state_type;


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

void *util_Malloc (size_t size)
{
   void *p;
   errno = 0;
   p = malloc (size);
   if (p == NULL) {
      error (EXIT_FAILURE, errno, "\nERROR: malloc failed:\n");
      return NULL;     /* to eliminate a warning from the compiler */
   } else
      return p;
}

void *util_Calloc (size_t count, size_t esize)
{
   void *p;
   errno = 0;
   p = calloc (count, esize);
   if (p == NULL) {
      error (EXIT_FAILURE, errno, "\nERROR: calloc failed:\n");
      return NULL;     /* to eliminate a warning from the compiler */
   } else
      return p;
}

void *util_Free (void *p)
{
   if (p == NULL)
      return NULL;
   free (p);
   return NULL;
}

/* 
 * ===  FUNCTION  ======================================================================
 *         Name:  init_buf
 *  Description:  read_size => maximum read_size used for fread
 *                Maximum amount of data requested form buffer: 4 bytes
 *                Worst case scenario: we need 4 bytes from buffer but buffer has only 3 bytes remaining
 *                We will fill the buffer with read_size bytes => minimum size of buffer is 3 + read_size 
 * =====================================================================================
 */
int
init_buf ( rng_buf_type* data, int read_size )
{
  const int max_number_of_bytes_requested_at_one_time = 4;
  data->read_size = read_size;
  data->buf	= (unsigned char*) malloc ( read_size + max_number_of_bytes_requested_at_one_time );
  if (  data->buf==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  }
  data->total_size = read_size + max_number_of_bytes_requested_at_one_time;
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
fill_buf ( rng_buf_type* data, unsigned int min_length_of_valid_data, output_sta_type* output_sta )
{
  unsigned int bytes_read;
  unsigned int bytes_requested;
  unsigned int bytes_to_fill_the_buffer;
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
get_unsigned_int_buf ( rng_buf_type* data, output_sta_type* output_sta )
{
  unsigned char* temp;
  static const unsigned int bytes_needed=4;   //TestU01 requires exactly 32bits
  unsigned int result;

  if (  bytes_needed > data->total_size ) {
    fprintf ( stderr, "\nBuffer does not support such big data sizes\n" );
    fprintf ( stderr, "\nBytes requested: %u, buffer size: %u\n", bytes_needed, data->total_size);
    exit (EXIT_FAILURE);
  }

  if ( bytes_needed > data->valid_data_size ) {
    fill_buf (data, data->read_size > bytes_needed ? data->read_size : bytes_needed, output_sta );
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
  return get_unsigned_int_buf(&internal_status, NULL);
}

static unsigned long STDIN_U01_Bits (void *param, void *state) {
  unsigned int result;

  STDIN_state_type* STDIN_state = state;
  
  result = get_unsigned_int_buf( &STDIN_state->rng_buf, &STDIN_state->output_sta);
  ++STDIN_state->output_sta.number_of_32_bits;

  return result;
}

static double STDIN_U01_Double (void *param, void *state) {
  return STDIN_U01_Bits (param, state) / 4294967296.0;
}

static void STDIN_U01_State (void *state) {

  STDIN_state_type* STDIN_state = state;
  output_sta_type* output_sta = &STDIN_state->output_sta;

  printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
  printf("%llu 32-bits random numbers were used for the test. This corresponds to\n",  output_sta->number_of_32_bits);
  printf("%llu bytes values and ",  output_sta->number_of_32_bits * 4LLU);
  printf("%llu MiB values.\n",  output_sta->number_of_32_bits/262144LLU);
  printf("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");



  output_sta->number_of_32_bits = 0;

  
}

unif01_Gen *create_STDIN_U01 ()
{
  unif01_Gen *gen;
  STDIN_state_type *state;
  output_sta_type* output_sta;
  size_t leng;
  char name[160];

  
  gen = util_Malloc (sizeof (unif01_Gen));
  gen->state = state = util_Malloc (sizeof (STDIN_state_type));
  output_sta = &state->output_sta;


  output_sta->number_of_32_bits = 0;
  init_buf(&state->rng_buf, 8192);


  gen->param = NULL;
  gen->Write = STDIN_U01_State;
  gen->GetU01 = STDIN_U01_Double;
  gen->GetBits = STDIN_U01_Bits;


  leng = strlen (name);
  gen->name = util_Calloc (leng + 2, sizeof (char));
  strncpy (gen->name, name, leng);

  return gen;
}

void delete_STDIN_U01 (unif01_Gen * gen)
{
  STDIN_state_type *state = gen->state;
  //output_sta_type* output_sta = &state->output_sta;
  



  destroy_buf (&state->rng_buf);

  gen->state = util_Free (state);
  gen->name = util_Free (gen->name);
  util_Free (gen);
}

//{{{ double double_pow(double x, uint8_t e)
//Computes x^e
double double_pow(double x, uint8_t e)
{
  if (e == 0) return 1;
  if (e == 1) return x;

  double tmp = double_pow(x, e/2);
  if (e%2 == 0) return tmp * tmp;
  else return x * tmp * tmp;
}
//}}}

static struct argp_option options[] = {
  { 0,                                0,      0,  0,  "\33[4mTests\33[m" },
  {"small",                         's',      0,  0,  "Small Crush Battery of Randomness tests" },
  { 0,                                0, 0,       0,  "" },
  {"normal",                        'n',      0,  0,  "Crush Battery of Randomness tests" },
  { 0,                                0, 0,       0,  "" },
  {"big",                           'b',      0,  0,  "Big Crush Battery of Randomness tests"},
  { 0,                                0, 0,       0,  "" },
  {"repeat",                        'r',"TEST:COUNT",  0,  "Repeat test number \"TEST\" from Crush Battery of Randomness tests \"COUNT\" times"}, 
  { 0,                                0, 0,       0,  "" },
  {"repeat-small",                  700,"TEST:COUNT",  0,  "Repeat test number \"TEST\" from Small Crush Battery of Randomness tests \"COUNT\" times"}, 
  { 0,                                0, 0,       0,  "" },
  {"repeat-big",                    701,"TEST:COUNT",  0,  "Repeat test number \"TEST\" from Big Crush Battery of Randomness tests \"COUNT\" times"}, 
  { 0,                                0, 0,       0,  "" },
  {"Rabbit",                        800,  "EXP",  0,       "Applies the Rabbit battery of tests to the STDIN using at most 2^EXP bits for each test. Minimum value 13 (~1KiB)" },
  { 0,                                0, 0,       0,  "" },
  {"Alphabit",                      801,  "EXP:R:S",  0,       "Applies the Alphabit battery of tests at most 2^EXP bits for each test. "
    "The bits themselves are processed as blocks of 32 bits (unsigned integers). For each block of 32 "
    "bits, the R most significant bits are dropped, and the test is applied on the S following bits. If one "
    "wants to test all bits of the stream, one should set R = 0 and S = 32. If one wants to test only 1 "
    "bit out of 32, one should set S = 1."}, 
  { 0,                                0, 0,       0,  "" },
  {"time",                          't',  "NUM",  OPTION_ARG_OPTIONAL,  "Run speed test of RNG, using NUM 32-bit random numbers. NUM is parsed as double number. Default: 1e8"},
  {"cat",                           'c', 0,       0,  "Act as UNIX cat command, read data from STDIN and put it on STDOUT"},
  { 0 }
};

typedef struct {
  int exp;
  int r;
  int s;
} rs_type;  //See Alphabit test


/* Used by main to communicate with parse_opt. */
struct arguments {
  int sflag;
  int nflag;
  int bflag;
  int rflag_s;
  int rflag_n;
  int rflag_b;
  rs_type aflag;
  int rabbitflag;
  long int tflag;
  int rep_n[NUMBER_OF_CRUSH_TESTS];
  int rep_s[NUMBER_OF_SMALL_CRUSH_TESTS];
  int rep_b[NUMBER_OF_BIG_CRUSH_TESTS];
  int cflag;
};

static struct arguments arguments = {
  .sflag = 0,
  .nflag = 0,
  .bflag = 0,
  .rflag_s = 0,
  .rflag_n = 0,
  .rflag_b = 0,
  .aflag.exp = 0,
  .rabbitflag = 0,
  .tflag = 0,
  .cflag = 0,
}; 

static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;
  int limit;
  int* flag_pointer;
  int* rep_pointer;
  char* name[3];
  name[0]="repeat-small";
  name[1]="repeat";
  name[2]="repeat-big";
  char* name_to_print;

  switch (key) {
    case 's':
      arguments->sflag = 1;
      break;
    case 'n':
      arguments->nflag = 1;
      break;
    case 'b':
      arguments->bflag = 1;
      break;
    case 800: {
      long l;
      char *p;
      l = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (l < 13) || (l > 50) )
        argp_error(state, "ERROR when parsing argument of --Rabbit option \"%s\". "
            "Expecting number in range < 13 - 50 >. Number is expected as integer, see \"man strtol\" for details.", arg);
      arguments->rabbitflag = l;
      break;
      }
    case 801: {
      long int n;
      char *p, *p1, *p2;
      n =  strtol(arg, &p, 10);
      if ((p == arg) || (*p != ':') || errno == ERANGE || (n < 13) || (n > 50) )
           argp_error(state, "ERROR when parsing argument EXP of --Alphabit option \"%s\". "
               "Expecting number in range < 13 - 50 >. Format is EXP:R:S. Substring is \"%s\"", arg, p);
      arguments->aflag.exp = n;

      p++; //Skip ':'
      n = strtol(p, &p1, 10);
       if ((p1 == p) || (*p1 != ':') || errno == ERANGE || (n < 0) || (n > 31) )
           argp_error(state, "ERROR when parsing argument R of --Alphabit option \"%s\". "
               "Expecting number in range < 0 - 31 >. Format is EXP:R:S. Substrings are \"%s\" \"%s\"", arg, p, p1);
       arguments->aflag.r = n;

      p1++; //Skip ':'
      n = strtol(p1, &p2, 10);
       if ((p2 == p1) || (*p2 != 0) || errno == ERANGE || (n < 0) || (n > 32) )
           argp_error(state, "ERROR when parsing argument S of --Alphabit option \"%s\". "
               "Expecting number in range < 0 - 32 >. Format is EXP:R:S. Substrings are \"%s\" \"%s\" \"%s\"", arg, p, p1, p2);
       arguments->aflag.s = n;

       if ( arguments->aflag.r + arguments->aflag.s > 32 ) {
         argp_error(state, "ERROR when parsing arguments R & S of --Alphabit option \"%s\". "
             "R + S has to be <= 32. Provided values are R: %d and S %d\n", arg, arguments->aflag.r, arguments->aflag.s);

       }
       break;
      }          
    case 700:
      limit = NUMBER_OF_SMALL_CRUSH_TESTS - 2;
      flag_pointer = &arguments->rflag_s;
      rep_pointer = arguments->rep_s;
      name_to_print = name[0];
    case 701:
      if ( key == 701 ) {  
        limit = NUMBER_OF_BIG_CRUSH_TESTS - 2;
        flag_pointer = &arguments->rflag_b; 
        rep_pointer = arguments->rep_b;
        name_to_print = name[2];
      }
    case 'r': {
      long int n,value;
      char *p;
      char *p1;
      if ( key == 'r') {
        limit = NUMBER_OF_CRUSH_TESTS - 2;
        flag_pointer = &arguments->rflag_n; 
        rep_pointer = arguments->rep_n;
        name_to_print = name[1];
      }
      n = strtol(arg, &p, 10);
      if ( n<0 || n > (NUMBER_OF_CRUSH_TESTS - 2) ) {
        argp_error(state, "Test number has to be in range 0 - %d. Processing input: \"%s\"", limit, arg);
        break;
      }
      if ((p == arg) || (*p != ':')) {
        argp_error(state, "--%s takes the format N:M where N is number of the test and M is count. Processing input: \"%s\", substring is \"%s\"", name_to_print, arg, p);
        break;
      }
      p++;
      value = strtol(p, &p1, 10);
      if ((p1 == p) || (*p1 != 0) || errno == ERANGE || (value < 0) || (value >= INT_MAX) || ( value > 1000 ) ) {
        argp_error(state, "Number of tests has to be in range 0 - %d. Processing input: \"%s\", substring is \"%s\"", 1000, arg, p);
        break;
      }
      rep_pointer[n] = value;
      *flag_pointer = 1;
      break;
    }
    case 't':
      if (arg == NULL) {
        arguments->tflag = 100000000;
      } else {
        double d;
        long l;
        char *p;
         d = strtod(arg, &p);
         if ((p == arg) || (*p != 0) || errno == ERANGE || (d < 1.0) || (d > LONG_MAX + 0.49) )
           argp_error(state, 
               "ERROR when parsing argument of -t option \"%s\". Expecting number in range < 1 - %ld >. Number is expected in double notation, see \"man strtod\" for details.", arg, LONG_MAX);
         else {
           l = (long int ) ( d + 0.5);
           if ( l < 1 ) 
               argp_error(state,  "ERROR when parsing -t during conversion from double %.16g value to long int %ld\n value. Expecting number long int >= 1\n", d, l);
           else 
            arguments->tflag = l;
         } 
      }
      break;

    case 'c':
      arguments->cflag = 1;
      break;
    case ARGP_KEY_ARG:
      argp_error(state,  "No arguments are supported, only options\n");
      break;
    case ARGP_KEY_END:
      if ( arguments->tflag == 0 &&
          arguments->rflag_s == 0 &&
          arguments->rflag_n == 0 &&
          arguments->rflag_b == 0 &&
          arguments->sflag == 0 &&
          arguments->nflag == 0 &&
          arguments->bflag == 0 &&
          arguments->aflag.exp == 0 &&
          arguments->rabbitflag == 0 &&
          arguments->cflag == 0) {
        argp_error(state,  "At least one of the options [-s] [-n] [-b] [-t[NUM]] [-c] \n"
            "[--repeat=TEST:COUNT] [--repeat-small=TEST:COUNT] [--repeat-big=TEST:COUNT] [--cat] has to be used\n");
      }
      if (arguments->cflag == 1 && 
           ( arguments->tflag == 1 ||
          arguments->rflag_s == 1 ||
          arguments->rflag_n == 1 ||
          arguments->rflag_b == 1 ||
          arguments->sflag == 1 ||
          arguments->nflag == 1 ||
          arguments->bflag == 1 ||
          arguments->aflag.exp == 1 ||
          arguments->rabbitflag == 1 ) ) {
        argp_error(state,  "When option -c is used following options are disabled [-s] [-n] [-b] [-t[NUM]] \n");
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

const char *argp_program_version = "Version 1.0\nCopyright (c) 2011-2012 by Jirka Hladky";
const char *argp_program_bug_address = "< hladky DOT jiri AT gmail DOT com >";
static char doc[] ="\33[1m\33[4mExecute TestU01 tests of randomness reading data from the standard input\33[m";

/* Our argp parser. */
static struct argp argp = { options, parse_opt, 0, doc };


int main (int argc, char **argv) 
{
  int i;
  for(i=0;i<NUMBER_OF_CRUSH_TESTS;++i) {
    arguments.rep_n[i] = 0;
  }
  for(i=0;i<NUMBER_OF_SMALL_CRUSH_TESTS;++i) {
    arguments.rep_s[i] = 0;
  }
  for(i=0;i<NUMBER_OF_BIG_CRUSH_TESTS;++i) {
    arguments.rep_b[i] = 0;
  }

  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  unif01_Gen *gen1;
  gen1 = create_STDIN_U01 ();

  if (arguments.cflag) {
    unsigned long data;
#ifdef HANDLE_ENDIANES
    unsigned long data_big_endian;
#endif
    while(1) {
      data = gen1->GetBits(gen1->param, gen1->state);
#ifdef HANDLE_ENDIANES      
      data_big_endian = htonl(data);
      fwrite(&data_big_endian, 4, 1, stdout);
#else
      fwrite(&data, 4, 1, stdout);
#endif
    }
    return 0;
  }

  if (arguments.tflag) unif01_TimerSumGenWr (gen1, arguments.tflag, TRUE);

  if (arguments.rflag_s) bbattery_RepeatSmallCrush (gen1, arguments.rep_s); 
  if (arguments.rflag_n) bbattery_RepeatCrush (gen1, arguments.rep_n); 
  if (arguments.rflag_b) bbattery_RepeatBigCrush (gen1, arguments.rep_b); 
    
  if (arguments.sflag) bbattery_SmallCrush (gen1);
  if (arguments.nflag) bbattery_Crush (gen1);
  if (arguments.bflag) bbattery_BigCrush (gen1);
  if (arguments.rabbitflag )  bbattery_Rabbit (gen1, double_pow(2.0,arguments.rabbitflag));
  if (arguments.aflag.exp )  bbattery_Alphabit (gen1, double_pow(2.0,arguments.aflag.exp), arguments.aflag.r, arguments.aflag.s);


  delete_STDIN_U01(gen1);

  return 0;
}

