/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/*
gcc -g -I ../include -I.. -L../src/.libs -Wextra -Wall -o generate_random_data generate_random_data.c -lcrypto -lcsprng -lm
LD_LIBRARY_PATH=../src/.libs ./generate_random_data

mkdir -p /tmp/tmpfs
sudo mount -t tmpfs -o size=20m tmpfs /tmp/tmpfs
LD_LIBRARY_PATH=../src/.libs ./generate_random_data > /tmp/tmpfs/a
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

// {{{ includes and macros
#define PROGNAME "generate_random_data"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <argp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#include <csprng/havege.h>
#include <csprng/helper_utils.h>
#include "config.h"
// }}}

// {{{ Documentation with examples for --help option
const char *argp_program_version = "GNU generate_random_data version " VERSION "\nCopyright (C) 2011-2012 by Jirka Hladky\n\n"
  "This is free software; see the source for copying conditions.  There is NO\n"
  "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"    
  "Written by Jirka Hladky";
const char *argp_program_bug_address = "<" PACKAGE_BUGREPORT ">";
static char doc[] = 
"Utility to write stream of random bytes to STDOUT or to the named pipe (FIFO) or to the file based on the HAVEGE algorithm"
  "\vExamples:\n"
  "csprng-generate -v -n 10.5M -o /tmp/random\n\t"
  "Write 10.5MB of random data to the file /tmp/random\n\n"
  "csprng-generate -n 10K --entropy_source=HTTP_RNG \\\n"
  "--additional_source=SHA1_RNG -f -r -m 16 -v | cat -A\n\t"
  "Produce 10KB of FIPS validated random numbers. CSPRNG generator will produce \n\t"
  "maximum of 16 CTR_DRBG blocks between reseeds.\n\t"
  "It will use different true random generators available on the web \n\t"
  "as entropy source and SHA1 RNG as additional input\n\t"
  "source to update the state of CSPRNG generator.\n\t"
  "It's recommended to register at http://random.irb.hr/\n\t"
  "and define login credentials using environment variables\n\t"
  "QRBG_USER=name and QRBG_PASSWD=password to enable\n\t"
  "fast and high quality TRNG http://random.irb.hr/\n\n"
  "(csprng-generate -n 2000 | tr -cd '[:graph:]' | fold -w 20 && echo ) |\n"
  "head -20\n\t"
  "Generate 20 random ASCII passwords of the length 20 characters\n\n"
  "(csprng-generate -n 2000 --entropy_source=MT_RNG | tr -cd '[:alnum:]' |\n"
  "fold -w 20 && echo ) | head -20\n\t"
  "Generate 20 random passwords of length 20 build from all letters and digits.\n\t"
  "Use Mersenne Twister generator (instead of HAVEGE) as the entropy source.\n\n"
  "QRBG_USER=name QRBG_PASSWD=password csprng-generate \\\n"
  "--entropy_source=HTTP_RNG -f -r -m16 -n 3705 | uuencode -m - | head -n 66 |\n"
  "tail -n 65 | gpg --symmetric -a > keyfile.gpg\n\t"
  "Create GPG encrypted keyfile for aespipe. Encrypt: \n\t"
  "tar -cvf - files... | bzip2 | aespipe -w 10 -K keyfile.gpg >archive.aes\n\t"
  "Decrypt: aespipe -d -K keyfile.gpg < /tmp/archive.aes | bzip2 -d -q | tar -tvf -\n\n"
  "time csprng-generate -f -v --additional_file=/dev/urandom -n3.5G -o /dev/null \\\n --write_statistics=2\n\t"
  "Measure time to generate 3.5G of FIPS validated random numbers. Use data\n\t"
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
  "for CSPRNG generator. Furthermore, SHA1_RNG cryptographically secured\n\t"
  "random generator is used as additional input. Again, it's preprocessed\n\t"
  "through derivation function first. Finally, only blocks passing\n\t"
  "FIPS 140-2 tests are sent to the output. Please note\n\t"
  "the advantage over the rngtest/rngd. Output data are guaranteed to be\n\t"
  "cryptographically secure. The generator acts as the entropy expander.\n\n"
  "csprng-generate --entropy_file=/dev/urandom\n"
  "--additional_source=HAVEGE -r -d -v | pv > /dev/null\n\t"
  "Here csprng-generate is using Linux random device /dev/urandom\n\t"
  "as the entropy input and HAVEGE as the additional input.\n\t"
  "Data are first processed through a derivation function and\n\t"
  "number of blocks produced between reseeds is randomized.\n\t"
  "It's recommended to run csprngd or other linux daemon to regularly refill\n\t"
  "the entropy of the kernel random device.\n\n"
  "csprng-generate | nc -k -l 3333\n\t"
  "Send RANDOM bytes to the netcat TCP server listening on the local machine\n\t"
  "on the port 3333. Data can be read for example with netcat:\n\t"
  "nc localhost 3333 | pv -rb > /dev/null\n\t"
  "One can use pv tool (Pipe Viewer) on the server side to\n\t"
  "specify input buffer size and statistics on bytes sent out:\n\t"
  "csprng-generate | pv -rb -B 1m | nc -k -l 3333\n\n"
  "PIPE=$(mktemp --dry-run) ; mkfifo ${PIPE}; \\\nQRBG_USER=name QRBG_PASSWD=password csprng-generate -m 8192 \\\n"
  "--entropy_source=HTTP_RNG -v -o ${PIPE} &\n"
  "csprng-generate |\n"
  "csprng-generate --entropy_file=${PIPE} --additional_source=STDIN |              "
  "dieharder -g 200 -a ; rm ${PIPE}\n\t"
  "Advanced usage example where one csprng-generate process is used to supply \n\t"
  "entropy via named pipe and other csprng-generate process is used to supply \n\t"
  "additional input via STDIN to the main csprng-generate process.\n\t"
  "Please note that CSPRNG acts as the entropy expander. For this example\n\t"
  "64 bytes of entropy input and 128 bytes of additional input are consumed\n\t"
  "to generate 16384 output bytes.\n\n"
;
// }}}

// {{{ Arguments definition
/* Used by main to communicate with parse_opt. */
struct arguments {
  int verbose;                        //Verbosity level
  uint64_t size;                      //Number of bytes to generate
  char *size_string;                  //Number of bytes as requested
  char *output_file;                  //Filename
  char unlimited;                     //1=> unlimited stream, 0=>limited stream
  int havege_data_cache_size;         //CPU data cache SIZE in KiB for HAVEGE. Default 0 (auto-detected)
  int havege_inst_cache_size;         //CPU instruction cache SIZE in KiB for HAVEGE. Default 0 (auto-detected)
  long int write_statistics;          //Dump statistics at given time interval (seconds). 0 to disable. setitimer(2) requires long
};

/* Default values. */
static struct arguments arguments = {
  .verbose = 0,
  .output_file = NULL,
  .size = 0,
  .unlimited = 1,
  .size_string = NULL,
  .havege_data_cache_size = 0,
  .havege_inst_cache_size = 0,
  .write_statistics = 0
};
#if GCC_VERSION > 40500
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
/* Command line options */
static struct argp_option options[] = {
  {"verbose",                       'v', 0,       0,  "Verbosity level. Two verbosity levels are supported. Second level (most verbose) is activated with -v -v" },
  {"output",                        'o', "FILE",  0,  "Output to FILE. Default: output goes to standard output" },
  {"write_statistics",              604,    "N",  0,  "Write to stderr number of generated bytes and results "
                                                      "of FIPS tests every \"N\" seconds. 0 to disable. Default: disabled" },
  {"number",                        'n', "BYTES", 0,  "Number of output BYTES, prefixes [k|m|g|t] for kibi, mebi, gibi and tebi are supported. Default: unlimited stream"},
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
    case 'o':
      arguments->output_file = arg;
      break;
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
// Writes number_of_bytes in human readable form (using prefixes Ki, Mi) and throughput 
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
//TODO: enum HAVEGE, SHA1, HTTP=> with options, MEMT, OPENSSL
int main(int argc, char **argv) {

//{{{ Variables  
  int exit_status = EXIT_SUCCESS;
  int rc;
  char havege_buf[2048];
  const DATA_TYPE* buf;

  int bytes_to_write;
  uint64_t remaining_bytes, total_bytes_written, bytes_generated;
  int is_fifo;
  FILE* fd_out;

  struct stat file_stat;
  struct timespec start_time;
  struct itimerval alarm_value;
  clock_gettime(CLOCK_REALTIME, &start_time);
  struct sigaction sigact;
  time_t current_time;
  char current_time_string[32];
//}}}
  
//{{{ Parse command line options and print Summary
  argp_parse (&argp, argc, argv, ARGP_NO_ARGS, 0, &arguments);

  if ( arguments.verbose ) {
    fprintf(stderr, "=============== %s SETUP ===============\n", PROGNAME);

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

    if ( arguments.write_statistics ) fprintf (stderr, "WRITE OUT STATISTICS EVERY = %ld seconds\n",  arguments.write_statistics);
    fprintf (stderr, "VERBOSE = %s, LEVEL = %d\n",  arguments.verbose ? "yes" : "no", arguments.verbose);
    fprintf (stderr, "===================================================================\n");
  }
//}}}  

// {{{ Init
  rc = havege_init( arguments.havege_inst_cache_size, arguments.havege_data_cache_size, 0);
  if ( rc ) {
    fprintf(stderr, "ERROR: havege_init has returned %d\n",rc);
    return 1;
  }

  if ( arguments.verbose > 1 ) {
    havege_status(havege_buf, 2048);
    fprintf(stderr,"================HAVEGE STATUS REPORT================\n");
    fprintf(stderr, "%s\n", havege_buf);
    fprintf(stderr,"====================================================\n");
  }

  total_bytes_written = 0;
  if ( ! arguments.unlimited ) {
    remaining_bytes = arguments.size;
  } else {
    //To make GCC happy
    remaining_bytes = 0;
  } 
// }}}

//{{{ Open output file
  if ( arguments.output_file == NULL ) {
    fd_out = stdout;
  } else {

    is_fifo = 0;
    if( access( arguments.output_file, F_OK ) != -1 ) {
      // file exists
      // Check for FIFO
      rc = stat(arguments.output_file, &file_stat);
      if ( rc == -1 ) {
        error(EXIT_FAILURE, errno,"stat(%s) has failed.\n", arguments.output_file);
      }
      if ( S_ISFIFO (file_stat.st_mode) ) {
        //FIFO pipe
        //We could open pipe in read write mode which will open the pipe immediately without waiting for the reader
        //fd_out = fopen ( arguments.output_file, "w+" );
        fprintf(stderr, "Output file \'%s\' is a FIFO. Please note that program will block until the consumer opens the FIFO for reading.\n", arguments.output_file);
        is_fifo = 1;
      }
    }

    fd_out = fopen ( arguments.output_file, "w" );
    if ( fd_out == NULL ) error(EXIT_FAILURE, errno,"Cannot open file '%s' for writing.\n", arguments.output_file);
    if ( is_fifo ) fprintf(stderr, "FIFO was successfully opened for writing.\n\n");
  }
//}}}
 
//{{{ Signal handling
  sigemptyset( &sigact.sa_mask );
  sigact.sa_flags = 0;
  sigact.sa_handler = signal_record_sigterm;

  if ( sigaction(SIGINT,  &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  if ( sigaction(SIGTERM, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  if ( sigaction(SIGPIPE, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }

  sigact.sa_flags = SA_RESTART;
  sigact.sa_handler = signal_record_sigusr1;
  if ( sigaction(SIGUSR1, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
  if ( sigaction(SIGALRM, &sigact, NULL) != 0 ) { error(EXIT_FAILURE, 0, "ERROR: sigaction has failed.\n"); }
//}}}

//{{{ Main loop
  bytes_generated = sizeof(DATA_TYPE) * HAVEGE_NDSIZECOLLECT;

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

    buf = ndrand_full_buffer();
    if ( arguments.unlimited || remaining_bytes > bytes_generated ) {
      bytes_to_write = bytes_generated;
    } else {
      bytes_to_write = remaining_bytes;
    }

    rc = fwrite (buf, sizeof(unsigned char), bytes_to_write, fd_out);

    if ( rc <  bytes_to_write )  {
      fprintf(stderr, "ERROR: fwrite '%s' - bytes written %d, bytes to write %d, errno %d\n", 
          arguments.output_file == NULL ? "stdout" : arguments.output_file,
          rc, bytes_to_write, errno);
      exit_status = EXIT_FAILURE;
      error(0, errno, "ERROR: fwrite '%s'", arguments.output_file == NULL ? "stdout" : arguments.output_file );
      break;
    }

    total_bytes_written += bytes_to_write;
    if ( ! arguments.unlimited ) { 
      remaining_bytes -= bytes_to_write;
    }

    if ( gotsigusr1 ) {
      gotsigusr1 = 0;
      current_time = time(NULL);
      strftime(current_time_string, sizeof(current_time_string) , "%a %b %H:%M:%S %Y", localtime(&current_time));
      fprintf ( stderr, "\n========================= %s ==========================\n", current_time_string );
      //if ( arguments.entropy_source == HTTP_RNG || arguments.add_input_source == HTTP_RNG ) {
      //  http_random_status( fips_state->csprng_state->http, 1);
      //}
      print_statistics(total_bytes_written, arguments.unlimited, remaining_bytes, arguments.size, stderr, &start_time);
      fprintf(stderr, "\n");
      fprintf ( stderr, "==========================================================================\n");
    }

    if ( gotsigterm) break;

  }
//}}}


  if ( arguments.output_file != NULL ) {
    rc = fclose(fd_out);
    if ( rc ) {
      exit_status = EXIT_FAILURE;
      error(0, errno, "ERROR: fclose '%s'", arguments.output_file);
    }
  }

  current_time = time(NULL);
  strftime(current_time_string, sizeof(current_time_string) , "%a %b %H:%M:%S %Y", localtime(&current_time));
  fprintf ( stderr, "\n======FINAL REPORT======= %s ==========================\n", current_time_string );
//  if ( arguments.entropy_source == HTTP_RNG || arguments.add_input_source == HTTP_RNG ) {
//    http_random_status( fips_state->csprng_state->http, 1);
//  }
  print_statistics(total_bytes_written, arguments.unlimited, remaining_bytes, arguments.size, stderr, &start_time);
  fprintf(stderr, "\n");

  if ( remaining_bytes > 0 ) {
    fprintf(stderr, "ERROR: Early end of the program.\nBytes requested: %" PRIu64 ". Bytes missing: %" PRIu64 "\n", arguments.size, remaining_bytes );
  }

  if ( arguments.unlimited ) {
    fprintf(stderr, "Requested unlimited stream.\n");
  }

  fprintf ( stderr, "==========================================================================\n");



  havege_destroy();
  
  return(exit_status);

}


