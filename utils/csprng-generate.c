/*
Main program to write random numbers to stdout or to the file

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

./csprng-generate | dd of=/dev/null bs=4096 count=100000
./csprng-generate | pv > /dev/null
./csprng-generate | dieharder -g 200 -a
*/

#include <stdlib.h>
#include <stdio.h>

#include <csprng/csprng.h>


#include <error.h>
#include <argp.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include "config.h"

/* Value added to key to get the key of the opposite option*/
#define OPP 256

/* This is to compile the program on older systems like RHEL4
 * Alternative: compile with -std=c99 (long long int is C99 feature)
 * Problems with -std=c99: timespec is not defined in time.h
To fix -std=c99 problem, following is needed:
http://stackoverflow.com/questions/3875197/std-c99-wtf-on-linux
#if __STDC_VERSION__ >= 199901L
#define _XOPEN_SOURCE 600
#else
#define _XOPEN_SOURCE 500
#endif
The stanza at the top is what I currently use - it triggers the definitions from Single UNIX Specification (SUS) based on whether you're using a C99 or C89 compiler.

If you want the POSIX 2008 (SUS v4) material, use _XOPEN_SOURCE 700
If you want the POSIX 2004 (SUS v3) material, use _XOPEN_SOURCE 600
If you want the POSIX 1995 (SUS v2, 1997) material, use _XOPEN_SOURCE 500
For my systems, POSIX 2008 is not as widely available as 2004, so that's what I use - but YMMV. Note that SUS v3 and v4 both require C99 compilation. On Solaris, at least, using C89 will fail.
*/

#ifndef ULLONG_MAX                                                                                                                                                                                                   
#define ULLONG_MAX 18446744073709551615ULL                                                                                                                                                                                      
#endif 

/*
Mode of operation of CTR_DRBG
DRBG =  deterministic random bit generator
CTR =   Counter (CTR) mode of operation of the block cipher (AES-128)
random input - supplied by HAVEGE
Mode of operation:
DF =0 , AD_INPUT=0  => random input is used only to reseed CTR_DRBG. 
DF =0 , AD_INPUT=1  => random input is used to reseed CTR_DRBG and to update the state of CTR_DRBG
DF = 1, AD_INPUT=0  => random input is used only to reseed CTR_DRBG. Random input is first processed through DERIVATION_FUNCTION
DF = 1, AD_INPUT=1  => random input is used to reseed CTR_DRBG and to update the state of CTR_DRBG. Random input is first processed through DERIVATION_FUNCTION

Reseed control:
How many NIST_BLOCK_OUTLEN_BYTES are generated before reseed (and additional_input if enabled) are applied?
Either fixed number MAX is used (default 512) or random number in range [1, MAX] for higher security
*/

const char *argp_program_version = "Version " VERSION "\nCopyright (c) 2011-2012 by Jirka Hladky";
const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";
static char doc[] ="\33[1m\33[4mUtility to write stream of random bytes to STDOUT or to the file.\33[m";

/*
 * Default: write endless stream of random bytes to STDOUT
 * Options -o <FILENAME>      Write to the file
 *         -n size<kmgt>      Write given amount of data
 *         -f                 Enable FIPS validation. Only FIPS validated blocks of random data are sent to the output
 *         -a                 Enable "additional input". It's used during reseed and also to update state of CTR_DRBG in "generate" phase.
 *         -d                 Use DERIVATION FUNCTION. It will process HAVEGE output through DERIVATION FUNCTION before reseed/change the state of CTR_DRBG
 *         -m                 Maximum number of CTR_DRBG blocks produced before reseed is performed
 *         -r                 Randomize number of CTR_DRBG blocks produced before reseed is performed. It's using uniform distribution [1,max]
 * --havege_data_cache_size   CPU data cache SIZE in KiB for HAVEGE algorithm
 * --havege_inst_cache_size   CPU instruction cache size in KiB for HAVEGE algorithm
 *         -v                 Verbose output
 */

/* Used by main to communicate with parse_opt. */
struct arguments {
  int verbose;                  //Verbosity level
  unsigned long long int size;  //Number of bytes to generate
  char *size_string;            //Number of bytes as requested
  char *output_file;            //Filename
  int unlimited;                //1=> unlimited stream, 0=>limited stream
  int fips_test;                //FIPS validation
  int derivation_function;      //Use DERIVATION FUNCTION?                         1=>true, 0=false
  int additional_input;         //Use additional input for prediction resistance   1=>true, 0=false
  int max_num_of_blocks;        //Maximum number MAX of CTR_DRBG blocks produced before reseed is performed
  int randomize_num_of_blocks;  //Randomize number of CTR_DRBG blocks produced before reseed is performed. 1=>true, 0=false
  int havege_data_cache_size;   //CPU data cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  int havege_inst_cache_size;   //CPU instruction cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
};

/* Default values. */
static struct arguments arguments = {
  .verbose = 0,
  .fips_test = 0,
  .output_file = NULL,
  .size = 0,
  .unlimited = 1,
  .size_string = NULL,
  .additional_input = 0,
  .derivation_function = 0,
  .max_num_of_blocks = 512,
  .randomize_num_of_blocks = 0,
  .havege_data_cache_size = 0,
  .havege_inst_cache_size = 0,
};

/* Command line options */
static struct argp_option options[] = {
  {"verbose",                       'v', 0,       0,  "Produce verbose output" },
  {"output",                        'o', "FILE",  0,  "Output to FILE. Default: output goes to standard output" },
  {"number",                        'n', "BYTES", 0,  "Number of output BYTES, prefixes [k|m|g|t] for kibi, mebi, gibi and tebi are supported. Default: unlimited stream"},
  { 0,                                0, 0,       0,  "\33[4mFIPS 140-2 validation:\33[m" },
  {"fips",                          'f', 0,       0,  "Only data valiadated by FIPS 140-2 random number tests are written out. Default: no FIPS 140-2 tests are performed"},
  {"no-fips",                   'f'+OPP, 0, OPTION_HIDDEN,  "No FIPS 140-2 tests are performed"},
  { 0,                                0, 0,       0,  "\33[4mMode of operation of CTR_DRBG:\33[m" },
  {"derivation_function",           'd', 0,       0,  "Use DERIVATION FUNCTION. It will process HAVEGE output through DERIVATION FUNCTION "
                                                      "before reseed/change the state of CTR_DRBG. Default: DERIVATION FUNCTION is not used"},
  {"no-derivation_function",    'd'+OPP, 0, OPTION_HIDDEN,  "Do not use DERIVATION FUNCTION"},
  { 0,                                0, 0,       0,  "" },
  {"additional_input",              'a', 0,       0,  "Use additional input. Output of HAVEGE is used to both reseed and update the state of CTR_DRBG. Default: additional input is not used"},
  {"no-additional_input",       'a'+OPP, 0, OPTION_HIDDEN,  "Do not use additional input"},
  { 0,                                0, 0,       0,  "" },
  {"max_num_of_blocks",             'm', "MAX",   0,  "Maximum number MAX of CTR_DRBG blocks produced before reseed is performed. Default: 512"},
  { 0,                                0, 0,       0,  "" },
  {"randomize_num_of_blocks",       'r', 0,   0,      "Randomize number of CTR_DRBG blocks produced before reseed is performed. "
                                                      "When enabled, uniform distribution [1,MAX] is used to get the number of generated CTR_DRBG blocks between reseeds. "
                                                      "When disabled, MAX of CTR_DRBG blocks is produced each time"},
  { 0,                                0, 0,       0,  "" },
  {"no-randomize_num_of_blocks",'r'+OPP, 0, OPTION_HIDDEN,  "Produce MAX of CTR_DRBG blocks each time"},
  { 0,                                0, 0,       0,  "\33[4mHAVEGE parameters:\33[m" },
  {"havege_data_cache_size",        600, "SIZE",  0,  "CPU data cache SIZE in KiB. Default: auto detected." },
  {"havege_inst_cache_size",        601, "SIZE",  0,  "CPU instruction cache size in KiB. Default: auto detected." },
  { 0 }
};

/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;
  char *suffix;
  int exp = 0;

  switch (key)
  {
    case 'v':
      arguments->verbose = 1;
      break;
    case 'd':
      arguments->derivation_function = 1;
      break;
    case 'd'+OPP:
      arguments->derivation_function = 0;
      break;
    case 'a':
      arguments->additional_input = 1;
      break;
    case 'a'+OPP:
      arguments->additional_input = 0;
      break;
    case 'r':
      arguments->randomize_num_of_blocks = 1;
      break;
    case 'r'+OPP:
      arguments->randomize_num_of_blocks = 0;
      break;
    case 'f':
      arguments->fips_test = 1;
      break;
    case 'f'+OPP:
      arguments->fips_test = 0;
      break;
    case 'o':
      arguments->output_file = arg;
      break;
    case 'm':{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n >= INT_MAX) || ( n>= NIST_CTR_DRBG_MAX_NUMBER_OF_BITS_PER_REQUEST) )
       argp_error(state, "Maximum number of CTR_DRBG blocks produced before reseed is performed should be in range 1 - %llu", NIST_CTR_DRBG_MAX_NUMBER_OF_BITS_PER_REQUEST);
       //argp_usage(state);
      else
        arguments->max_num_of_blocks = n;
      break;
    }
    case 600:{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n >= INT_MAX) || ( n> 16384 ) )
       argp_error(state, "CPU data cache SIZE in KiB for HAVEGE should be in range 1 - %d.", 16384);
       //argp_usage(state);
      else
        arguments->havege_data_cache_size = n;
      break;
    }
    case 601:{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 0) || (n >= INT_MAX) || ( n> 16384 ) )
       argp_error(state, "CPU instruction cache SIZE in KiB for HAVEGE should be in range 1 - %d.", 16384);
       //argp_usage(state);
      else
        arguments->havege_inst_cache_size = n;
      break;
    }
    case 'n':{
      double size_as_double;
      arguments->size_string = arg;
      size_as_double = strtod(arg, &suffix);
      if ((arg == suffix) || errno == ERANGE || (size_as_double < 0) || (size_as_double >= ULLONG_MAX) ) {
        argp_error(state, "Size has to be in range <0, %llu>. Processing input: \"%s\", suffix is \"%s\"", ULLONG_MAX, arg, suffix);
        break;
      }
      if ( strlen(suffix) > 0 ) {
        if ( strlen(suffix) > 1 )  argp_error(state, "Only one character long suffixes are supported. Processing input: \"%s\", suffix is \"%s\"", arg, suffix);
        switch(*suffix) {
          case 't': case 'T':
            exp = 40 ;
            break;
          case 'g': case 'G':
            exp = 30 ;
            break;
          case 'm': case 'M':
            exp = 20 ;
            break;
          case 'k': case 'K':
            exp = 10;
            break;
          default:
	    argp_error(state, "Unknown suffix '%s' when parsing '%s'.\n", suffix, arg);
        }
        size_as_double = ldexp(size_as_double, exp);
        if (  errno == ERANGE ) { argp_error(state, "ERANGE error detected when computing ldexp(%g, %d)\n",size_as_double, exp ); }
      }
      size_as_double = ceil(size_as_double);
       if ( (size_as_double < 0) || (size_as_double >= ULLONG_MAX) ) {
         argp_error(state, "Size has to be in range <0, %llu>. Processing input: \"%s\", suffix is \"%s\". Size as double value is %g\n", ULLONG_MAX, arg, suffix, size_as_double);
       }

      arguments->size = (unsigned long long int) ( size_as_double );
      assert( arguments->size == size_as_double );
      arguments->unlimited = 0 ;
      break;
    }
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, 0, doc };

int main(int argc, char **argv) {

  int exit_status = EXIT_SUCCESS;
  FILE* fd_out;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, ARGP_NO_ARGS, 0, &arguments);

  if ( arguments.verbose == 1 ) {
    fprintf (stderr, "OUTPUT_FILE = %s\n"
        "VERBOSE = %s\nFIPS 140-2 VALIDATION = %s\n"
        "USE DERIVATION FUNCTION = %s\nUSE ADDITIONAL INPUT = %s\n"
        "MAXIMUM NUMBER OF CTR_DRBG BLOCKS PRODUCED BETWEEN RESEEDs = %d\n"
        "RANDOMIZE NUMBER OF CTR_DRBG BLOCKS PRODUCED BETWEEN RESEEDs = %s\n"
        "SIZE = %llu bytes\nREQUESTED SIZE = %s\nENDLESS STREAM = %s\n",
        arguments.output_file,
        arguments.verbose                  ? "yes" : "no",
        arguments.fips_test                ? "yes" : "no",
        arguments.derivation_function      ? "yes" : "no",
        arguments.additional_input         ? "yes" : "no",
        arguments.max_num_of_blocks,
        arguments.randomize_num_of_blocks  ? "yes" : "no",
        arguments.size,
        arguments.size_string,
        arguments.unlimited                ? "yes" : "no"
        );
    if ( arguments.havege_data_cache_size ) {
      fprintf (stderr, "HAVEGE CPU data cache size = %d\n", arguments.havege_data_cache_size);
    } else {
      fprintf (stderr, "HAVEGE CPU data cache size = AUTO DETECTED\n");
    }
    if ( arguments.havege_inst_cache_size ) {
      fprintf (stderr, "HAVEGE CPU instruction cache size = %d\n", arguments.havege_inst_cache_size);
    } else {
      fprintf (stderr, "HAVEGE CPU instruction cache size = AUTO DETECTED\n");
    }

  }

  if ( arguments.output_file == NULL ) {
    fd_out = stdout;
  } else {
    fd_out = fopen ( arguments.output_file, "w" );
    if ( fd_out == NULL ) error(EXIT_FAILURE, errno,"Cannot open file '%s' for writing.\n", arguments.output_file);
  }

  int return_code, bytes_generated;
  fips_state_type   fips_state;
  mode_of_operation_type mode_of_operation;

  unsigned char *output_buffer;
  int output_buffer_size = 8192 ;
  int bytes_to_write;
  unsigned long long int remaining_bytes, total_bytes_written;


  if ( ! arguments.unlimited ) {
    remaining_bytes = arguments.size;
  } else {
    total_bytes_written = 0;
  } 

  output_buffer	= (unsigned char*) malloc ( output_buffer_size * sizeof(unsigned char) );
  if ( output_buffer ==NULL ) {
    error(EXIT_FAILURE, errno,"Dynamic memory allocation failed\n");
  } 

  mode_of_operation.use_df                        = arguments.derivation_function;
  mode_of_operation.use_additional_input          = arguments.additional_input;
  mode_of_operation.havege_debug_flags            = 0;
  mode_of_operation.havege_status_flag            = arguments.verbose;           
  mode_of_operation.havege_data_cache_size        = arguments.havege_data_cache_size;        
  mode_of_operation.havege_instruction_cache_size = arguments.havege_inst_cache_size; 

  return_code = fips_approved_csprng_init(&fips_state, arguments.fips_test, 
      arguments.max_num_of_blocks, arguments.randomize_num_of_blocks, 0,
      &mode_of_operation);

  if ( return_code ) {
    error(EXIT_FAILURE, errno, "ERROR: fips_approved_csprng_init has returned %d\n",return_code);
  }

#if 0    
    return_code = fwrite (&fips_state.fips_ctx.last32, 1, sizeof(fips_state.fips_ctx.last32), fd_out);
    if ( return_code <  4 )  {
      exit_status = EXIT_FAILURE;
      error(0, errno, "ERROR: fwrite '%s'", arguments.output_file);
      return(exit_status);
    }
#endif

  while( arguments.unlimited || remaining_bytes > 0 ) {
    bytes_generated = fips_approved_csprng_generate(&fips_state, output_buffer, output_buffer_size);

    if ( bytes_generated < output_buffer_size ) {
      if (arguments.unlimited || remaining_bytes > bytes_generated ) {
        fprintf( stderr, "ERROR: fips_approved_csprng_generate has returned %d Bytes instead of %d Bytes requested.\n", 
            bytes_generated, output_buffer_size);
        if ( bytes_generated == 0 ) break;
      }
    }

    if ( arguments.unlimited || remaining_bytes > bytes_generated ) {
      bytes_to_write = bytes_generated;
    } else {
      bytes_to_write = remaining_bytes;
    }

    return_code = fwrite (output_buffer, sizeof(unsigned char), bytes_to_write, fd_out);
    if ( return_code <  bytes_to_write )  {
      exit_status = EXIT_FAILURE;
      error(0, errno, "ERROR: fwrite '%s'", arguments.output_file);
      break;
    }
    if ( ! arguments.unlimited ) { 
      remaining_bytes -= bytes_to_write;
    } else {
      total_bytes_written += bytes_to_write;
      if ( bytes_generated < output_buffer_size ) {
        break;
      }
    }
  }

  if ( arguments.unlimited ) {
    fprintf(stderr, "ERROR: Premature end of the program. Requested unlimited stream, bytes written out: %llu\n",
        total_bytes_written);
  } else if ( remaining_bytes > 0 ) {
    fprintf(stderr, "ERROR: Premature end of the program. Bytes requested: %llu, Bytes written out: %llu, Bytes missing: %llu\n",
        arguments.size, arguments.size - remaining_bytes, remaining_bytes );
  } else {
    fprintf(stderr, "Bytes written out: %llu\n", arguments.size - remaining_bytes);
  }

  if ( arguments.output_file != NULL ) {
    return_code = fclose(fd_out);
    if ( return_code ) {
      exit_status = EXIT_FAILURE;
      error(0, errno, "ERROR: fclose '%s'", arguments.output_file);
    }
  }

  return_code = fips_approved_csprng_destroy(&fips_state);
  if ( return_code ) {
    error(EXIT_FAILURE, errno, "ERROR: fips_approved_csprng_destroy has returned %d\n",return_code);
  }

  return(exit_status);
}
