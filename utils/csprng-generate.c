/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Preamble
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
./csprng-generate --fips --output-fips-init -r | rngtest -t 60

}}} */

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

// {{{ includes and macros

#define PROGNAME "csprng-generate"

#include <stdlib.h>
#include <stdio.h>

#include <csprng/csprng.h>
#include <csprng/helper_utils.h>


#include <error.h>
#include <argp.h>
#include <string.h>
#include <math.h>
#include <assert.h>
#include <signal.h>
#include <time.h>
//setitimer
#include <sys/time.h>

#include "config.h"

/* Value added to key to get the key of the opposite option*/
#define OPP 256

/* HTTP_RNG rate in Bytes/s */
const long double  HTTP_RNG_RATE = 200;

/* CSPRNG rate in Bytes/s (200 MB/s) */
const long double CSPRNG_RATE = 209715200;

/* CSPRNG rate with final FIPS validation in Bytes/s (20 MB/s) */
const long double CSPRNG_RATE_WITH_FIPS = 20971520;

/* HTTP_RNG reasonable length */
const long double HTTP_REASONABLE_LENGTH = 32768.0L;


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

#define GCC_VERSION (__GNUC__ * 10000 \
                               + __GNUC_MINOR__ * 100 \
                               + __GNUC_PATCHLEVEL__)

//Macro to get the current source line as string
//#define STRINGIFY(x) #x
//#define TOSTRING(x) STRINGIFY(x)
//#define AT "LINE NUMBER: " TOSTRING(__LINE__) " "
// }}}

/* {{{ Description of CSPRNG
Mode of operation of CTR_DRBG
DRBG =  deterministic random bit generator
CTR =   Counter (CTR) mode of operation of the block cipher (AES-128 in this program)
random input - supplied by HAVEGE or read from file
Mode of operation:
DF =0 , AD_INPUT=0  => random input is used only to reseed CTR_DRBG. 
DF =0 , AD_INPUT=1  => random input is used to reseed CTR_DRBG and to update the state of CTR_DRBG
DF = 1, AD_INPUT=0  => random input is used only to reseed CTR_DRBG. Random input is first processed through DERIVATION_FUNCTION
DF = 1, AD_INPUT=1  => random input is used to reseed CTR_DRBG and to update the state of CTR_DRBG. Random input is first processed through DERIVATION_FUNCTION

Reseed control:
How many NIST_BLOCK_OUTLEN_BYTES are generated before reseed (and additional_input if enabled) are applied?
Either fixed number MAX is used (default 512) or random number in range [1, MAX] for higher security

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
 }}} */

// {{{ Documentation with examples for --help option
#if 0
#define BOLD      "\33[1m"
#define UNDERLINE "\33[4m"
#define NORMAL    "\33[m"
#else
#define BOLD      ""
#define UNDERLINE ""
#define NORMAL    ""
#endif

const char *argp_program_version = "GNU csprng-generate version " VERSION "\nCopyright (c) 2011-2012 by Jirka Hladky\n\n"
  "This is free software; see the source for copying conditions.  There is NO\n"
  "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"    
  "Written by Jirka Hladky";
const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";
static char doc[] = BOLD UNDERLINE "Utility to write stream of random bytes to STDOUT or to the file." NORMAL
  "\vExamples:\n"
  "csprng-generate -v -n 10.5M -o /tmp/random\n\t"
  "Write 10.5MB of random data to the file /tmp/random\n\n"
  "(csprng-generate -n 2000 | tr -cd '[:graph:]' | fold -w 20 && echo )|head -20\n\t"
  "Generate 20 random ASCII passwords of the length 20 characters\n\n"
  "(csprng-generate -n 2000 --entropy_source=MT_RNG | tr -cd '[:alnum:]' |        fold -w 20 && echo )|head -20\n\t"
  "Generate 20 random passwors of length 20 build from all letters and digits.\n\t"
  "Use Mersenne Twister generator (instead of HAVEGE) as the entropy source.\n\n"
  "csprng-generate -f -r -m16 -n 3705 | uuencode -m - | head -n 66 | tail -n 65 | gpg --symmetric -a > keyfile.gpg\n\t"
  "Create GPG encrypted keyfile for aespipe. Encrypt: \n\t"
  "tar cvf - files... | bzip2 | aespipe -w 10 -K keyfile.gpg >archive.aes\n\t"
  "Decrypt: aespipe -d -K keyfile.gpg < /tmp/archive.aes | bzip2 -d -q | tar tvf -\n\n"
  "csprng-generate --additional_source=SHA1_RNG -f -r -m 16 -v | cat -A\n\t"
  "Produce FIPS validated random numbers. CSPRNG generator will produce maximum\n\t"
  "of 16 CTR_DRBG blocks between reseeds.\n\t"
  "It will use HAVEGE RNG as entropy source and SHA1 RNG as additional input\n\tsource to update the state of CSPRNG generator.\n\n"
  "time csprng-generate -f -v --additional_file=/dev/urandom -n3.5G -o /dev/null \\ --write_statistics=2\n\t"
  "Measure time to generate 3.5G of FIPS valaidated random numbers. Use data\n\t"
  "from /dev/urandom to update state of CSPRNG generator. Write statistics\n\t"
  "to stderr every 2 seconds.\n\n"
  "csprng-generate -d -m8 -r --additional_source=SHA1_RNG | cat -A\n\t"
  "Produce endless stream of high quality random numbers. CSPRNG generator will\n\t"
  "process HAVEGE hardware random numbers and SHA1_RNG random numbers through\n\t"
  "derivation function first before updating it's state. Furthermore, maximum\n\t"
  "of 8 CTR_DRBG blocks will be produced between reseeds\n\n"
  "csprng-generate | dieharder -g 200 -a\n\t"
  "Test the randomness of the generated data with dieharder test suite\n\n"
  "csprng-generate --entropy_file=/dev/hwrng --additional_source=SHA1_RNG -d -f\n\t"
  "This shows how to use csprng-generate es replacement of rngtest/rngd.\n\t"
  "Random bytes from any hardware random generator (/dev/hwrng in this example)\n\t"
  "are preprocessed through derivation function and used as entropy source\n\t"
  "for CSPRNG generator. Furthermore, SHA1_RNG crypthographically secured\n\t"
  "random generator is used as additional input. Again, it's preprocessed\n\t"
  "through derivation function first. Finally, only blocks passing\n\t"
  "FIPS 140-2 tests are sent to the output. Please note\n\t"
  "the advantage over the rngtest/rngd. Output data are guaranteed to be\n\t"
  "cryptographically secure. The generator acts as entropy expander.\n\n"
  "PIPE=$(mktemp --dry-run) ; mkfifo ${PIPE}; csprng-generate -v -o ${PIPE} &      "
  "csprng-generate |                                                               "
  "csprng-generate --entropy_file=${PIPE} --additional_source=STDIN |              "
  "dieharder -g 200 -a ; rm ${PIPE}\n\t"
  "Advanced example where one csprng-generate process is used to supply entropy\n\t"
  "via named pipe and other csprng-generate process is used to supply \n\t"
  "additional input via STDIN to the main csprng-generate process.\n\t"
  "Please note that CSPRNG acts as the entropy expander. For this example\n\t"
  "64 bytes of entropy input and 128 bytes of additional input are consumed\n\t"
  "to generate 16384 output bytes.\n\n"
;
// }}}

// {{{ Arguments definiton
/* Used by main to communicate with parse_opt. */
struct arguments {
  int verbose;                        //Verbosity level
  uint64_t size;                      //Number of bytes to generate
  char *size_string;                  //Number of bytes as requested
  char *output_file;                  //Filename
  char unlimited;                     //1=> unlimited stream, 0=>limited stream
  int fips_test;                      //FIPS validation
  int derivation_function;            //Use DERIVATION FUNCTION?                         1=>true, 0=false
  uint64_t max_num_of_blocks;         //Maximum number MAX of CTR_DRBG blocks produced before reseed is performed
  int randomize_num_of_blocks;        //Randomize number of CTR_DRBG blocks produced before reseed is performed. 1=>true, 0=false
  int havege_data_cache_size;         //CPU data cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  int havege_inst_cache_size;         //CPU instruction cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  int output_fips_init_bits;          //Write out FIPS 140-2 initialization data (32-bits for long test). 0 => FALSE, 1 => TRUE
  char *entropy_file;                 //Filename for entropy source (NULL means HAVEGE)
  char *add_input_file;               //Filename for additional input source (NULL means HAVEGE)
  rand_source_type entropy_source;    //Source of entropy - HAVEGE, MT, EXTERNAL ?
  rand_source_type add_input_source;  //Source of additional input - HAVEGE, MT, EXTERNAL ?
  int entropy_source_set;             //Has been used option --entropy_source ?
  int additional_source_set;          //Has been used option --additional_source ?
  long int write_statistics;          //Dump statistics at given time interval (seconds). 0 to disable. setitimer(2) requires long
};

/* Default values. */
static struct arguments arguments = {
  .verbose = 0,
  .fips_test = 0,
  .output_file = NULL,
  .size = 0,
  .unlimited = 1,
  .size_string = NULL,
  .derivation_function = 0,
  .max_num_of_blocks = 512,
  .randomize_num_of_blocks = 0,
  .havege_data_cache_size = 0,
  .havege_inst_cache_size = 0,
  .output_fips_init_bits = 0,
  .entropy_file = NULL,
  .add_input_file = NULL,
  .entropy_source = HAVEGE,
  .add_input_source = NONE,
  .entropy_source_set = 0,
  .additional_source_set = 0,
  .write_statistics = 0
};
#if GCC_VERSION > 40500
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
/* Command line options */
static struct argp_option options[] = {
  {"verbose",                       'v', 0,       0,  "Verbosity level. Two verbosity levels are supported. Second level (most verbose) is activated with \'-v -v\'" },
  {"output",                        'o', "FILE",  0,  "Output to FILE. Default: output goes to standard output" },
  {"write_statistics",              604,    "N",  0,  "Write to stderr number of generated bytes and results "
                                                      "of FIPS tests every \"N\" seconds. 0 to disable. Default: disabled" },
  {"entropy_source",                801, "SOURCE",0,  "Specify SOURCE of RANDOM bytes for CTR_DRBG entropy input instead of HAVEGE algorithm. "
                                                      "One of the following can be used HAVEGE|SHA1_RNG|MT_RNG|HTTP_RNG|STDIN|EXTERNAL. Default: HAVEGE."},
  {"entropy_file",                  802, "FILE",  0,  "Use FILE as the source of RANDOM bytes for CTR_DRBG entropy input. "
                                                      "It implies --entropy-source=EXTERNAL"},
  {"number",                        'n', "BYTES", 0,  "Number of output BYTES, prefixes [k|m|g|t] for kibi, mebi, gibi and tebi are supported. Default: unlimited stream"},
  { 0,                                0, 0,       0,  UNDERLINE "FIPS 140-2 validation:" NORMAL },
  {"fips",                          'f', 0,       0,  "Only data valiadated by FIPS 140-2 random number tests are written out. "
                                                      "Default: no FIPS 140-2 tests are performed. Please note that parameter has "
                                                      "big impact on performance. On test system, performance went down from 170MB/s "
                                                      "to 17 MB/s after enabling FIPS valiadation."},
  {"no-fips",                   'f'+OPP, 0, OPTION_HIDDEN,  "No FIPS 140-2 tests are performed"},
  {"output-fips-init",              602, 0,       0,  "Write-out 32-bits used to initialize FIPS 140-2 tests. This is to sync with rngtest tool. "
                                                      "Default: do not write out these bits"},
  { 0,                                0, 0,       0,  UNDERLINE "Mode of operation of CTR_DRBG:" NORMAL },
  {"derivation_function",           'd', 0,       0,  "Use DERIVATION FUNCTION. It will process HAVEGE output through DERIVATION FUNCTION "
                                                      "before reseed/change the state of CTR_DRBG. Default: DERIVATION FUNCTION is not used"},
  {"no-derivation_function",    'd'+OPP, 0, OPTION_HIDDEN,  "Do not use DERIVATION FUNCTION"},
  { 0,                                0, 0,       0,  "" },
  {"additional_source",              851,"SOURCE",0,  "Use additional input. Specify SOURCE of RANDOM bytes for CTR_DRBG additional input. "
                                                      "One of the following can be used NONE|HAVEGE|SHA1_RNG|HTTP_RNG|MT_RNG|STDIN|EXTERNAL. Default: NONE."  },
  {"additional_file",                852, "FILE", 0,  "Use FILE as source of RANDOM bytes for CTR_DRBG additional_input. "
                                                      "It implies --additional_source=EXTERNAL."},
  { 0,                                0, 0,       0,  "" },
  {"max_num_of_blocks",             'm', "MAX",   0,  "Maximum number MAX of CTR_DRBG blocks produced before reseed is performed. Default: 512"},
  { 0,                                0, 0,       0,  "" },
  {"randomize_num_of_blks",       'r', 0,   0,      "Randomize number of CTR_DRBG blocks produced before reseed is performed. "
                                                      "When enabled, uniform random distribution [1,MAX] is used to get "
                                                      "the number of generated CTR_DRBG blocks between reseeds. "
                                                      "Default: MAX of CTR_DRBG blocks is produced each time"},
  { 0,                                0, 0,       0,  "" },
  {"no-randomize_num_of_blks",'r'+OPP, 0, OPTION_HIDDEN,  "Produce MAX of CTR_DRBG blocks each time"},
  { 0,                                0, 0,       0,  UNDERLINE "HAVEGE parameters:" NORMAL },
  {"havege_data_cache_size",        600, "SIZE",  0,  "CPU data cache SIZE in KiB. Default: auto detected." },
  {"havege_inst_cache_size",        601, "SIZE",  0,  "CPU instruction cache size in KiB. Default: auto detected." },
  { 0 }
};
#if GCC_VERSION > 40500
#pragma GCC diagnostic pop
#endif
// }}}

//{{{ Arguments parser
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
      ++arguments->verbose;
      break;
    case 'd':
      arguments->derivation_function = 1;
      break;
    case 'd'+OPP:
      arguments->derivation_function = 0;
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
    case 801:
      if ( strcmp("HAVEGE", arg) == 0 ) {
        arguments->entropy_source = HAVEGE;
      } else if ( strcmp("SHA1_RNG", arg) == 0 ) { 
        arguments->entropy_source = SHA1_RNG;
      } else if ( strcmp("MT_RNG", arg) == 0 ) {
        arguments->entropy_source = MT_RNG;
      } else if ( strcmp("HTTP_RNG", arg) == 0 ) {
        arguments->entropy_source = HTTP_RNG;
      } else if ( strcmp("STDIN", arg) == 0 ) {
        arguments->entropy_source = STDIN;
      } else if ( strcmp("EXTERNAL", arg) == 0 ) {
        arguments->entropy_source = EXTERNAL;
      } else {
        argp_error(state, "entropy_source can be one of HAVEGE|SHA1_RNG|MT_RNG|HTTP_RNG|STDIN|EXTERNAL. Got '%s'", arg);
      }
      arguments->entropy_source_set = 1;
      break;
    case 802:
      arguments->entropy_file = arg;
      break;
    case 851:
      if ( strcmp("NONE", arg) == 0) {
        arguments->add_input_source = NONE;
      } else if ( strcmp("HAVEGE", arg) == 0 ) {
        arguments->add_input_source = HAVEGE;
      } else if ( strcmp("SHA1_RNG", arg) == 0 ) { 
        arguments->add_input_source = SHA1_RNG;
      } else if ( strcmp("MT_RNG", arg) == 0 ) {
        arguments->add_input_source = MT_RNG;
      } else if ( strcmp("HTTP_RNG", arg) == 0 ) {
        arguments->entropy_source = HTTP_RNG;
      } else if ( strcmp("STDIN", arg) == 0 ) {
        arguments->add_input_source = STDIN;
      } else if ( strcmp("EXTERNAL", arg) == 0 ) {
        arguments->add_input_source = EXTERNAL;
      } else {
        argp_error(state, "Additional input source can be one of NONE|HAVEGE|SHA1_RNG|MT_RNG|HTTP_RNG|STDIN|EXTERNAL. Got '%s'", arg);
      }
      arguments->additional_source_set = 1;
      break;
    case 852:
      arguments->add_input_file = arg;
      break;  
    case 'm':{
      uint64_t n;
      int rc;
      uint64_t max = (uint64_t) ( NIST_CTR_DRBG_RESEED_INTERVAL ) / 8 / NIST_BLOCK_OUTLEN_BYTES;
      rc = sscanf(arg, "%" SCNu64 "", &n);
      if ( rc == 0 ) {
        argp_error(state, "Maximum number of CTR_DRBG blocks produced before reseed is performed should be in range 1 - %" PRIu64 ". "
            "Error when parsing %s. Reported error: %s\n", max, arg, strerror(errno));
      }
      if ( (n < 1) || ( n> max ) )
       argp_error(state, "Maximum number of CTR_DRBG blocks produced before reseed is performed should be in range 1 - %" PRIu64 ". Got %" PRIu64 ".", max, n);
      else
        arguments->max_num_of_blocks = n;
      break;
    }
    case 600:{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);  //See also strtoull
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
    case 602:
      arguments->output_fips_init_bits = 1;
      break;
    case 604:{
      long int n;
      char *p;
      long int max = LONG_MAX;
      //Maximum value for setitimer(2) system call is LONG_MAX
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 0) || (n > max))
       argp_error(state, "--write_statistics has to be in range 0-%ld\n", max);
      else
        arguments->write_statistics = n;
      break;
    }
    case 'n':{
      double size_as_double;
      arguments->size_string = arg;
      size_as_double = strtod(arg, &suffix);
      if ((arg == suffix) || errno == ERANGE || (size_as_double < 0) || (size_as_double >= UINT64_MAX) ) {
        argp_error(state, "Size has to be in range <0, %" PRIu64 ">. Processing input: \"%s\", suffix is \"%s\"", UINT64_MAX, arg, suffix);
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

      arguments->size = (uint64_t) ( size_as_double );
      assert( arguments->size == size_as_double );
      arguments->unlimited = 0 ;
      break;
    }
    case ARGP_KEY_ARG:
      argp_error(state, "No arguments are supported, only options\n");
      break;

    case ARGP_KEY_END:
      if (arguments->output_fips_init_bits) {
        if (arguments->fips_test == 0 ) {
          argp_error(state, "Argument output-fips-init can be used only when fips validation (--fips option) is enabled.\n");
        }
      }

      if (arguments->max_num_of_blocks == 1 && arguments->randomize_num_of_blocks) {
        argp_error(state, "When max_num_of_blocks == 1 there is no point to randomize number of blocks.\n"
           "Please either specify max_num_of_blocks to be >1 or disable randomization of number of blocks.\n");
      }

      //{{{ Are entropy sources input options consistent?
      if ( arguments->entropy_source == EXTERNAL &&  arguments->entropy_file == NULL ) {
        argp_error(state, "Option --entropy_source=EXTERNAL requires option --entropy_file=FILE to be specified.\n");
      }

      if ( arguments->entropy_file != NULL && arguments->entropy_source_set != 0 &&  arguments->entropy_source != EXTERNAL ) {
         argp_error(state, "Option --entropy_source=%s is not compactible with option --entropy_file=%s.\n"
             "Please note that in case when FILE source is intended then the option '--entropy_source=EXTERNAL' can be omitted.\n",
             source_names[arguments->entropy_source], arguments->entropy_file);
      }

      if ( arguments->entropy_file != NULL && arguments->entropy_source_set == 0 ) {
        arguments->entropy_source = EXTERNAL;
      }
      //}}}

      //{{{ Are additional input sources input options consistent?
      if ( arguments->add_input_source == EXTERNAL &&  arguments->add_input_file == NULL ) {
        argp_error(state, "Option --additional_source=EXTERNAL requires option --additional_file=FILE to be specified.\n");
      }

      if ( arguments->add_input_file != NULL && arguments->additional_source_set != 0 &&  arguments->add_input_source != EXTERNAL ) {
         argp_error(state, "Option --additional_source=%s is not compactible with option --additional_file=%s.\n"
             "Please note that in case when FILE source is intended then the option '--additional_source=EXTERNAL' can be omitted.\n",
             source_names[arguments->add_input_source], arguments->add_input_file);
      }

      if ( arguments->add_input_file != NULL && arguments->additional_source_set == 0 ) {
        arguments->add_input_source = EXTERNAL;
      }
      //}}}

      if ( arguments->entropy_source != HAVEGE && arguments->add_input_source != HAVEGE ) {
          if ( arguments->havege_data_cache_size != 0 ) {
            argp_error(state, "Option --havege_data_cache_size is not supported when no HAVEGE input is used.\n");
          }
          if ( arguments->havege_inst_cache_size != 0 ) {
            argp_error(state, "Option --havege_inst_cache_size is not supported when no HAVEGE input is used.\n");
          }
        }

      if ( arguments->write_statistics > 0  && ( arguments->entropy_source == HTTP_RNG || arguments->add_input_source == HTTP_RNG ) ) {
        if ( (double) HTTP_TIMEOUT_IN_SECONDS / (double) arguments->write_statistics > 0.05 ) {
          fprintf(stderr, "WARNING: HTTP source has been enabled. This can disrupt the frequency of statistics reports. "
              "HTTP can wait upto %d seconds before timing out. During this period, statistic output is supressed.\n", HTTP_TIMEOUT_IN_SECONDS);
        }
      }

      if ( arguments->verbose > 2 ) {
        fprintf(stderr, "WARNING: Maximum supported verbosity level is 2. Verbosity level will be reduced from %d to 2.\n", arguments->verbose);
        arguments->verbose = 2;
      }

      break;

default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
#if GCC_VERSION > 40500
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
static struct argp argp = { options, parse_opt, 0, doc };

#if GCC_VERSION > 40500
#pragma GCC diagnostic push
#endif
//}}}

//{{{ void signal_record_sigterm(int signal)
volatile sig_atomic_t gotsigterm = 0;   /* Received SIGTERM/SIGINT/SIGPIPE */

void signal_record_sigterm(int signal) {
  gotsigterm = signal;
}
//}}}

//{{{ void signal_record_sigusr1(int signal)
volatile sig_atomic_t gotsigusr1; /* SIGUSR1 => ==0 when no signal, ==1 when signal was received*/

void signal_record_sigusr1(int signal) {
  gotsigusr1 = signal;
}
//}}}

//{{{ void print_statistics(uint64_t number_of_bytes, FILE *stream, struct timespec* start_time)
// Writes number_of_bytes in human redable form (using prefixes Ki, Mi) and throughput 
// number_of_bytes: value to print out
// stream:          where to write the output
// start_time:      Time when counter number_of_bytes was started         

void print_statistics(uint64_t number_of_bytes, char unlimited, uint64_t remaining_bytes, uint64_t requested, FILE *stream, struct timespec* start_time) {

   long double throughput = 0.0L;
   int64_t time_milis;
   struct timespec current_time;
   static uint64_t previous_number_of_bytes = 0;
   static struct timespec previous_time = { 0, 0 };
   int64_t diff; 

   clock_gettime(CLOCK_REALTIME, &current_time);
   time_milis = elapsed_time( start_time, &current_time );
   fprintf(stream , "Bytes written out: %s.", human_print_int(number_of_bytes) );
   if ( !  unlimited ) {
     fprintf(stream , "%7.2Lf%%", (long double) number_of_bytes * 100.0L / (long double) requested ) ;
     fprintf(stream , " , remaining bytes: %s",  human_print_int(remaining_bytes) );
     //fprintf(stream , " from %s requested.",  human_print_int(requested) );
   }


   if ( time_milis != 0 ) {
     throughput = (long double) number_of_bytes / (long double) time_milis * (long double) 1000.0L;  //B/s
      //fprintf(stream , " Throughput raw B/s %Lg, time_milis %" PRIu64" milis\n", throughput, time_milis);
     fprintf(stream , "\nThroughput using real time %s/s.", human_print_ldouble(throughput) );
   }

   //{{{ Bytes written and throughput since the last print
   if ( previous_number_of_bytes  && number_of_bytes >= previous_number_of_bytes) {
     diff = number_of_bytes - previous_number_of_bytes;
     fprintf(stream , " Since the last print %s", human_print_int( diff ) ); 

     time_milis = elapsed_time( &previous_time, &current_time );
     if ( time_milis != 0 ) {
       throughput = (long double) diff / (long double) time_milis * (long double) 1000.0L;  //B/s
       fprintf(stream , ", speed using real time %s/s.", human_print_ldouble(throughput) );
     }
   }
   //}}}

   previous_number_of_bytes = number_of_bytes;
   previous_time = current_time;

} 
//}}}

//{{{ int main(int argc, char **argv)
int main(int argc, char **argv) {

  //{{{ Variables
  int exit_status = EXIT_SUCCESS;
  FILE* fd_out;

  int return_code;
  fips_state_type*  fips_state;
  mode_of_operation_type mode_of_operation;

  unsigned char *output_buffer;
  unsigned int output_buffer_size = 8192 ;
  int bytes_to_write;
  uint64_t remaining_bytes, total_bytes_written, bytes_generated;

  struct timespec start_time;
  struct itimerval alarm_value;
  clock_gettime(CLOCK_REALTIME, &start_time);
  struct sigaction sigact;
  time_t current_time;
  char current_time_string[32];
  //}}}

  //{{{ Parse comamnd line options 
  memset(&mode_of_operation, 0, sizeof(mode_of_operation_type));
  argp_parse (&argp, argc, argv, ARGP_NO_ARGS, 0, &arguments);
  //}}}

//{{{ Print Summary
  if ( arguments.verbose ) {
    fprintf(stderr, "=============== %s SETUP ===============\n", PROGNAME);
    if ( arguments.entropy_source == EXTERNAL ) {
      fprintf (stderr, "ENTROPY SOURCE = File '%s'\n", arguments.entropy_file);
    } else {
      fprintf (stderr, "ENTROPY SOURCE = %s\n", source_names[arguments.entropy_source]);
    }

    fprintf( stderr, "USE ADDITIONAL INPUT = %s\n", (arguments.add_input_source != NONE ) ? "yes" : "no" );
    if ( arguments.add_input_source != NONE ) {
      if ( arguments.add_input_source == EXTERNAL ) {
        fprintf (stderr, "ADDITIONAL INPUT SOURCE = File '%s'\n", arguments.add_input_file);
      } else {
        fprintf (stderr, "ADDITIONAL INPUT SOURCE = %s\n", source_names[arguments.add_input_source]);
      }
    }

    fprintf (stderr, 
        "USE DERIVATION FUNCTION = %s\n"
        "MAXIMUM NUMBER OF CTR_DRBG BLOCKS PRODUCED BETWEEN RESEEDs = %" PRIu64 "\n"
        "RANDOMIZE NUMBER OF CTR_DRBG BLOCKS PRODUCED BETWEEN RESEEDs = %s\n"
        "FIPS 140-2 VALIDATION = %s\n",
        arguments.derivation_function      ? "yes" : "no",
        arguments.max_num_of_blocks,
        arguments.randomize_num_of_blocks  ? "yes" : "no",
        arguments.fips_test                ? "yes" : "no");

    if ( arguments.fips_test ) fprintf(stderr, "OUTPUT FIPS INIT BITS = %s\n", arguments.output_fips_init_bits ? "yes" : "no");

    if ( arguments.output_file == NULL ) {
      fprintf(stderr, "OUTPUT_FILE = STDOUT\n");
    } else {
      fprintf(stderr, "OUTPUT_FILE = File '%s'\n", arguments.output_file);
    }

    fprintf (stderr,
        "SIZE = %" PRIu64 " bytes\nREQUESTED SIZE = %s\nENDLESS STREAM = %s\n",
        arguments.size,
        arguments.size_string,
        arguments.unlimited                ? "yes" : "no" );

    if (  arguments.entropy_source == HAVEGE || arguments.add_input_source == HAVEGE ) {
      if ( arguments.havege_data_cache_size ) {
        fprintf (stderr, "HAVEGE CPU data cache size = %d\n KiB\n", arguments.havege_data_cache_size);
      } else {
        fprintf (stderr, "HAVEGE CPU data cache size = AUTO DETECTED\n");
      }
      if ( arguments.havege_inst_cache_size ) {
        fprintf (stderr, "HAVEGE CPU instruction cache size = %d KiB\n", arguments.havege_inst_cache_size);
      } else {
        fprintf (stderr, "HAVEGE CPU instruction cache size = AUTO DETECTED\n");
      }
    }
    
    if ( arguments.write_statistics ) fprintf (stderr, "WRITE OUT STATISTICS EVERY = %ld seconds\n",  arguments.write_statistics);
    fprintf (stderr, "VERBOSE = %s, LEVEL = %d\n",  arguments.verbose ? "yes" : "no", arguments.verbose);
    fprintf (stderr, "===================================================================\n");
  }
//}}}  

//{{{ Initialize CSPRNG
  if ( arguments.output_file == NULL ) {
    fd_out = stdout;
  } else {
    fd_out = fopen ( arguments.output_file, "w" );
    if ( fd_out == NULL ) error(EXIT_FAILURE, errno,"Cannot open file '%s' for writing.\n", arguments.output_file);
  }
  
  mode_of_operation.entropy_source = arguments.entropy_source;
  if ( arguments.entropy_source == EXTERNAL ) {
    mode_of_operation.filename_for_entropy = arguments.entropy_file;
  } else {
    mode_of_operation.filename_for_entropy = NULL;
  }

  mode_of_operation.add_input_source = arguments.add_input_source;
  if ( arguments.add_input_source == EXTERNAL ) {
    mode_of_operation.filename_for_additional = arguments.add_input_file;
  } else {
    mode_of_operation.filename_for_additional = NULL; 
  }

  total_bytes_written = 0;
  if ( ! arguments.unlimited ) {
    remaining_bytes = arguments.size;
  } else {
    //To make GCC happy
    remaining_bytes = 0;
  } 

  output_buffer	= (unsigned char*) malloc ( output_buffer_size * sizeof(unsigned char) );
  if ( output_buffer ==NULL ) {
    error(EXIT_FAILURE, errno,"Dynamic memory allocation failed\n");
  } 

  mode_of_operation.use_df                        = arguments.derivation_function;
  mode_of_operation.havege_debug_flags            = 0;
  mode_of_operation.havege_status_flag            = ( arguments.verbose == 2 ) ? 1 : 0;
  mode_of_operation.havege_data_cache_size        = arguments.havege_data_cache_size;        
  mode_of_operation.havege_instruction_cache_size = arguments.havege_inst_cache_size;
  mode_of_operation.file_read_size = 16384;
  mode_of_operation.max_number_of_csprng_blocks   = arguments.max_num_of_blocks;
  mode_of_operation.random_length_of_csprng_generated_bytes = arguments.randomize_num_of_blocks;
  mode_of_operation.http_random_verbosity         = arguments.verbose;

  fips_state = fips_approved_csprng_initialize(arguments.fips_test, 0, &mode_of_operation);

  if ( fips_state == NULL ) {
    fprintf(stderr, "ERROR: fips_approved_csprng_initialize has failed.\n");
    exit(EXIT_FAILURE);
  }
  //}}}  

  //{{{ Expected size of the entropy and additional input
  if ( arguments.verbose > 1 || arguments.entropy_source == HTTP_RNG || arguments.add_input_source == HTTP_RNG ) {
    uint64_t output_buffer_size = fips_state->raw_buf->total_size + fips_state->out_buf->total_size;
    long double target_rate = arguments.fips_test ? CSPRNG_RATE_WITH_FIPS : CSPRNG_RATE;
    csprng_estimate_bytes_needed ( fips_state->csprng_state, arguments.unlimited, arguments.size, output_buffer_size,
        arguments.verbose, HTTP_REASONABLE_LENGTH, HTTP_RNG_RATE, target_rate);
  }
  //}}}  

  //{{{ Instantiate CSPRNG
  return_code = fips_approved_csprng_instantiate ( fips_state ) ;
  if ( return_code ) {
    fprintf(stderr, "ERROR: fips_approved_csprng_instantiate has failed.\n");
    exit(EXIT_FAILURE);
  }
  //}}}

  //{{{ Write out FIPS 32-bit long test seed 
  //this is to make sure that rngd will not fail fips testing
  //utils/csprng-generate --fips --output-fips-init -r | rngd --foreground --rng-device=/dev/stdin
  if ( arguments.output_fips_init_bits ) {
    if ( arguments.fips_test ) {
      return_code = fwrite (&fips_state->fips_ctx.last32, 1, sizeof(fips_state->fips_ctx.last32), fd_out);
      if ( return_code <  4 )  {
        exit_status = EXIT_FAILURE;
        error(0, errno, "ERROR: fwrite '%s'", arguments.output_file);
        return(exit_status);
      }
    }
  }
  //}}}

  //{{{ Signal handling
  sigemptyset( &sigact.sa_mask );
  sigact.sa_flags = 0;
  sigact.sa_handler = signal_record_sigterm;

  if ( sigaction(SIGINT,  &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  if ( sigaction(SIGTERM, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  if ( sigaction(SIGPIPE, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }

  sigact.sa_handler = signal_record_sigusr1;
  if ( sigaction(SIGUSR1, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  if ( sigaction(SIGALRM, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  //}}}

  //{{{ Main loop
  if ( arguments.write_statistics ) {
    alarm_value.it_value.tv_sec = arguments.write_statistics;
    alarm_value.it_value.tv_usec = 0;
    alarm_value.it_interval.tv_sec = arguments.write_statistics;
    alarm_value.it_interval.tv_usec = 0;
    if ( setitimer(ITIMER_REAL, &alarm_value, NULL) ) {
      error(EXIT_FAILURE, errno, "ERROR: setitimer has failed.\n");
    }
  }
  
  while( arguments.unlimited || remaining_bytes > 0 ) {
    bytes_generated = fips_approved_csprng_generate(fips_state, output_buffer, output_buffer_size);

    if ( bytes_generated < output_buffer_size ) {
      if (arguments.unlimited || remaining_bytes > bytes_generated ) {
        fprintf( stderr, "ERROR: fips_approved_csprng_generate has returned %" PRIu64 " Bytes instead of %u Bytes requested.\n", 
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

    total_bytes_written += bytes_to_write;
    if ( ! arguments.unlimited ) { 
      remaining_bytes -= bytes_to_write;
    } else {
      if ( bytes_generated < output_buffer_size ) {
        break;
      }
    }

    if ( gotsigusr1 ) {
      gotsigusr1 = 0;
      current_time = time(NULL);
      strftime(current_time_string, sizeof(current_time_string) , "%a %b %H:%M:%S %Y", localtime(&current_time));
      fprintf ( stderr, "\n========================= %s ==========================\n", current_time_string );
      if ( arguments.entropy_source == HTTP_RNG || arguments.add_input_source == HTTP_RNG ) {
        http_random_status( fips_state->csprng_state->http, 1);
      }
      print_statistics(total_bytes_written, arguments.unlimited, remaining_bytes, arguments.size, stderr, &start_time);
      fprintf(stderr, "\n");
      if ( arguments.fips_test) fprintf ( stderr, "%s", dump_fips_statistics ( &fips_state->fips_ctx.fips_statistics ) );
      fprintf ( stderr, "==========================================================================\n");
    }

    if ( gotsigterm) break;
  }
  //}}}

  //{{{ END of program - print final summary and do cleaning

  if ( arguments.output_file != NULL ) {
    return_code = fclose(fd_out);
    if ( return_code ) {
      exit_status = EXIT_FAILURE;
      error(0, errno, "ERROR: fclose '%s'", arguments.output_file);
    }
  }

  current_time = time(NULL);
  strftime(current_time_string, sizeof(current_time_string) , "%a %b %H:%M:%S %Y", localtime(&current_time));
  fprintf ( stderr, "\n======FINAL REPORT======= %s ==========================\n", current_time_string );
  if ( arguments.entropy_source == HTTP_RNG || arguments.add_input_source == HTTP_RNG ) {
    http_random_status( fips_state->csprng_state->http, 1);
  }
  print_statistics(total_bytes_written, arguments.unlimited, remaining_bytes, arguments.size, stderr, &start_time);
  fprintf(stderr, "\n");
  if ( arguments.fips_test) fprintf ( stderr, "%s", dump_fips_statistics ( &fips_state->fips_ctx.fips_statistics ) );

  if ( remaining_bytes > 0 ) {
    fprintf(stderr, "ERROR: Early end of the program.\nBytes requested: %" PRIu64 ". Bytes missing: %" PRIu64 "\n", arguments.size, remaining_bytes );
  }

  if ( arguments.unlimited ) {
    fprintf(stderr, "Requested unlimited stream. ");
  }

  fprintf ( stderr, "==========================================================================\n");


  if ( arguments.verbose > 1 ) fips_approved_csprng_statistics(fips_state);
  return_code = fips_approved_csprng_destroy(fips_state);
  if ( return_code ) {
    error(EXIT_FAILURE, errno, "ERROR: fips_approved_csprng_destroy has returned %d\n",return_code);
  }

  free(output_buffer);

  return(exit_status);
  //}}}

}
//}}}
