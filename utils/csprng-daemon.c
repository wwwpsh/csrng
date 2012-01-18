/* Daemon to fill entropy


   src/csprng | dd of=/dev/null bs=4096 count=100000
   src/csprng | pv > /dev/null
   src/csprng | /home/jirka/C/64-bit/2011-Jan-20-dieharder/dieharder-3.31.0_BIN/bin/dieharder -g 200 -a

   /home/jirka/C/64-bit/2011-Sep-16-HAVEGED/New_official_release/2011-Oct-20/haveged-1.3/src/haveged -n0 | dd of=/dev/null bs=4096 count=100000

*/


#include <stdlib.h>
#include <stdio.h>

#include <csprng/csprng.h>
#include "fips.h"

/*
 * Default: write endless stream of random bytes to STDOUT
 * Options -f <FILENAME> => write to the file
 *         -n size<kmgt> => write given amount of data
 */

#include <error.h>
#include <argp.h>
#include <string.h>
#include <math.h>

const char *argp_program_version ="csprng-generate 1.0";
const char *argp_program_bug_address ="<hladky DOT jiri AT gmail DOT com>";
static char doc[] ="Utility to write stream of random bytes";

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,       0,  "Produce verbose output" },
  {"output",   'o', "FILE",  0,  "Output to FILE instead of standard output" },
  {"number",   'n', "BYTES", 0,  "Number of output BYTES, prefixes [k|m|g|t] for kilo, mega, giga and tera are supported"},
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments {
  int verbose;          //Verbosity level
  double size;          //Number of bytes to generate
  char *size_string;    //Number of bytes as requested
  char *output_file;    //Filename
  int unlimited;        //1=> unlimited stream, 0=>limited stream
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
    case 'o':
      arguments->output_file = arg;
      break;
    case 'n':
      arguments->size_string = arg;
      arguments->size = strtod(arg, &suffix);
      if ( strlen(suffix) > 0 ) {
        if ( strlen(suffix) > 1 ) argp_usage (state);
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
            fprintf(stderr, "Unknown suffix '%s' when parsing '%s'\n", suffix, arg);
            argp_usage (state);
        }
        arguments->size = ldexp(arguments->size, exp);
      }
      arguments->size = ceil(arguments->size);
      if ( isfinite(arguments->size) ) {
        arguments->unlimited = 0 ;
      } else {
        arguments->unlimited = 1 ;
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, 0, doc };

struct settings {
  char *daemon;
  char *os_rel;
  char *pid_file;
  char *poolsize;
  char *random_device;
  char *wakeup_threshold      = "/proc/sys/kernel/random/write_wakeup_threshold"

                   int street_no;
  char *street_name;
  char *city;
  char *prov;
  char *postal_code;
};

struct min_max_statistics {
        uint64_t max;                   /* Highest value seen */
        uint64_t min;                   /* Lowest value seen */
        uint64_t num_samples;           /* Number of samples */
        uint64_t sum;                   /* Sum of all samples */
};

struct rng_stats {
	uint64_t bytes_received;	/* Bytes read from entropy source */
	struct rng_stat source_blockfill;  /* Block-receive time */

	struct rng_stat fips_blockfill;	/* FIPS-processing time */
	uint64_t bad_fips_blocks;	/* Blocks reproved by FIPS tests */
	uint64_t good_fips_blocks;	/* Blocks approved by FIPS tests */
	uint64_t 
	   fips_failures[N_FIPS_TESTS];	/* Breakdown of failed FIPS tests */
	
	uint64_t bytes_sent;		  /* Bytes sent to RNG sink */
	uint64_t entropy_sent;		/* Bits of entropy sent to ent. sink */
	uint64_t sink_starved;		/* How many times we waited for
					   FIPS-approved buffers to be ready */
	uint64_t buffer_lowmark;	/* Minimum number of ready buffers we
					   had after startup */
	struct min_max_statistics sink_wait;	/* Sink starvation wait */
};
static struct rng_stats rng_stats;



int main(int argc, char **argv) {
  memset(&rng_stats, 0, sizeof(rng_stats));
	rng_stats.buffer_lowmark = number_of_rng_buffers - 1; /* one is always in use */














  int exit_status = EXIT_SUCCESS;

  struct arguments arguments;
  /* Default values. */
  arguments.verbose = 0;
  arguments.output_file = NULL;
  arguments.size = INFINITY;
  arguments.unlimited = 1;
  arguments.size_string = NULL;

  FILE* fd_out;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, ARGP_NO_ARGS, 0, &arguments);

  if ( arguments.verbose == 1 ) {
    fprintf (stderr, "OUTPUT_FILE = %s\n"
        "VERBOSE = %s\nSIZE = %.14g bytes\nREQUESTED SIZE = %s\nENDLESS STREAM = %s\n",
        arguments.output_file,
        arguments.verbose ? "yes" : "no",
        arguments.size,
        arguments.size_string,
        arguments.unlimited ? "yes" : "no" );
  }

  if ( arguments.output_file == NULL ) {
    fd_out = stdout;
  } else {
    fd_out = fopen ( arguments.output_file, "w" );
    if ( fd_out == NULL ) error(EXIT_FAILURE, errno,"Cannot open file '%s' for writing.\n", arguments.output_file);
  }

  int return_code;
  csprng_state_type csprng_state;
  unsigned char *output_buffer;
  int output_buffer_size = 512 * NIST_BLOCK_OUTLEN_BYTES ;
  int bytes_to_write;

  output_buffer	= (unsigned char*) malloc ( output_buffer_size * sizeof(unsigned char) );
  if ( output_buffer ==NULL ) {
    error(EXIT_FAILURE, errno,"Dynamic memory allocation failed\n");
  } 

  return_code = csprng_init(&csprng_state, 0, 0, 0, arguments.verbose);
  if ( return_code ) {
    error(EXIT_FAILURE, errno, "Error: csprng_init has returned %d\n",return_code);
  }

  while( arguments.unlimited || arguments.size > 0 ) {
    return_code = csprng_generate(&csprng_state, output_buffer, output_buffer_size);
    if ( return_code ) {
      error(EXIT_FAILURE, errno, "Error: csprng_generate  has returned %d\n", return_code);
    }
    if ( arguments.unlimited || arguments.size >= output_buffer_size ) {
      bytes_to_write = output_buffer_size;
    } else {
      bytes_to_write = arguments.size;
    }

    return_code = fwrite (output_buffer, sizeof(unsigned char), bytes_to_write, fd_out);
    if ( return_code <  bytes_to_write )  {
      exit_status = EXIT_FAILURE;
      error(0, errno, "Error: fwrite '%s'", arguments.output_file);
      break;
    }
     if ( ! arguments.unlimited ) arguments.size -= bytes_to_write;
  }

  if ( arguments.output_file != NULL ) {
    return_code = fclose(fd_out);
     if ( return_code ) {
       exit_status = EXIT_FAILURE;
       error(0, errno, "Error: fclose '%s'", arguments.output_file);
     }
  }

  return_code = csprng_destroy(&csprng_state);
  if ( return_code ) {
    error(EXIT_FAILURE, errno, "Error: csprng_destroy has returned %d\n",return_code);
  }

  return(exit_status);
}
