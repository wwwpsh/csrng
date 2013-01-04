/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Preamble
Daemon to refill entropy of /dev/random device

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
}}} */

/* {{{ Copyright notice

Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>

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

/* {{{ Examples
1) Fill with csprngd 
\time taskset -c 1 ./utils/csprngd --foreground -v
Consumer:
\time  taskset -c 0 dd if=/dev/random count=8192 bs=8192 iflag=fullblock of=/dev/null

2) Fill with rngd 
utils/csprng-generate --fips --output-fips-init -r | rngd --foreground --rng-device=/dev/stdin
Same using specific CPU:
taskset -c 0 utils/csprng-generate --fips --output-fips-init -v | taskset -c 0 rngd --rng-device=/dev/stdin
Consumer:
dd if=/dev/random count=8192 bs=8192 iflag=fullblock of=/dev/null

3)Watch CPU load
mpstat -P ALL 2
}}} */

//{{{ includes
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include <csprng/csprng.h>
#include <csprng/helper_utils.h>


#include <error.h>
#include <argp.h>
#include <string.h>
#include <assert.h>

#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <poll.h>
//TODO RHEL4 needs /usr/include/linux/types.h
#include <linux/types.h>
//
#include <linux/random.h>
#include <syslog.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>   //mlock
#include <sys/file.h>   //flock

#include "random_interface_linux.h"
#include "config.h"

//getrlimit
#include <sys/time.h>
#include <sys/resource.h>

#if 0
#define BOLD      "\33[1m"
#define UNDERLINE "\33[4m"
#define NORMAL    "\33[m"
#else
#define BOLD      ""
#define UNDERLINE ""
#define NORMAL    ""
#endif

#define GCC_VERSION (__GNUC__ * 10000 \
                               + __GNUC_MINOR__ * 100 \
                               + __GNUC_PATCHLEVEL__)

/* HTTP_RNG rate in Bytes/s */
const long double  HTTP_RNG_RATE = 200;

/* CSPRNG rate in Bytes/s (200 MB/s) */
const long double CSPRNG_RATE = 209715200;

/* CSPRNG rate with final FIPS validation in Bytes/s (20 MB/s) */
const long double CSPRNG_RATE_WITH_FIPS = 20971520;

/* HTTP_RNG reasonable length */
const long double HTTP_REASONABLE_LENGTH = 32768.0L;


//}}}

//{{{ C-preprocessor define
#define PROGNAME "csprngd"

#define GENERATE_DATA_UPFRONT 1
//GENERATE_DATA_UPFRONT == 1 => We will fill the buffer before waiting for RANDOM device to need the data. 
//                              Thus, when the random data are needed, we have them ready. 
//                              Drawback: since we don't know how much data we need we will fill the whole
//                              buffer and then rewind the buffer with memmove. It can possible add some overhead
//GENERATE_DATA_UPFRONT == 0 => We will plug random generator after RANDOM device has signalized that it needs data. 
//                              Thus, there might be a delay to get the data. On the other hand we will request exactly
//                              the amount of data needed, no buffer rewind is needed                               


// Value added to key to get the key of the opposite option
#define OPP 256
//}}}

//{{{ Global variables
volatile sig_atomic_t gotsigterm = 0;   /* Received SIGTERM/SIGINT/SIGPIPE */
volatile sig_atomic_t gotsigusr1 = 0;   /* Received SIGUSR1/SIGALRM */

const char *argp_program_version = "GNU csprngd daemon version " VERSION "\nCopyright (c) 2011-2012 by Jirka Hladky\n\n"
  "This is free software; see the source for copying conditions.  There is NO\n"
  "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n"    
  "Written by Jirka Hladky";

const char *argp_program_bug_address =  "<" PACKAGE_BUGREPORT ">";
static char doc[] =BOLD UNDERLINE "Daemon to feed entropy from cryptographically secure pseudo-random number generator to the kernel entropy pool." NORMAL
"\vExamples:\n"
"csprngd -p /var/run/csprngd.pid \n\t"
"Run the daemon to refill the entropy. PID file will be stored\n\t"
"at /var/run/csprngd.pid. The operation is logged via syslog\n\t"
"and can be usually tracked at /var/log/syslog\n\n"
"csprngd -v -v --foreground --write_statistics=30\n\t"
"Run in the foreground in the most verbose mode\n\t"
"and output statics information every 30 seconds on the stderr\n\n"
"csprngd --upper_limit=75\%\n\t"
"Fill entropy level up to 75\% of kernel entropy pool-size. This is more\n\t"
"aggressive than the default mode. While offering slightly better performance,\n\t"
"the kernel entropy pool will be dominated by csprngd data.\n\t"
"See /proc/sys/kernel/random/poolsize for the kernel entropy poolsize.\n\n"
"csprngd --fill-interval=10\n\t"
"Refill kernel's entropy at least every 10 seconds to 50\% of the kernel\n\t"
"entropy pool size. Using this, available entropy will stay close to\n\t"
"50\% of the kernel entropy pool size. The kernel entropy pool\n\t"
"will be dominated by csprngd data. Without --fill-interval\n\t"
"entropy will be refilled only when it drops bellow value\n\t"
"specified at /proc/sys/kernel/random/write_wakeup_threshold\n\n"
"csprngd --derivation_function --additional_source=SHA1_RNG\n\t"
"Use built-in SHA1_RNG generator as additional input to DRBG. Both HAVEGE and\n\t"
"SHA1_RNG outputs are first processed through derivation function before\n\t"
"used to update the state of DRBG. This offers higher security compared\n\t"
"to the default behaviour where only HAVEGE is used to update DRBG\n\n"
"csprngd --entropy_file=/dev/hwrng\n\t"
"Use csprngd as replacement for rngd. /dev/hwrng is used to model True Random\n\t"
"Generator (TRNG). Any other file/device can be used instead.\n\t"
"Data from TRNG are used to update the state of DRBG. DRBG works\n\t"
"as entropy whitener and entropy expander. Final data are checked on-line\n\t"
"using FIPS PUB 140-2 test to guarantee that we send high entropy random data\n\t"
"to the kernel\n\n"
"csprngd -d --entropy_file=/dev/hwrng --additional_source=HAVEGE\n\t"
"Advanced replacement of the rngd. See also above. TRNG data are processed\n\t"
"first through the derivation function. On top of that HAVEGE RNG is used as\n\t"
"as the additional input of the DRBG\n\n"
"csprngd -d --entropy_file=/dev/hwrng --additional_source=SHA1_RNG --max_num_of_blocks=4096\n\t"
"Works as the entropy expander. Around 0.5MiB of the input entropy data\n\t"
"is needed to generate 1GiB of the random data for the kernel's device\n\t"
"in this particular configuration.\n\n"
"QRBG_USER=name QRBG_PASSWD=password csprngd --foreground"
"--write_statistics=30 --entropy_source=HTTP_RNG "
"--additional_source=HAVEGE --derivation_function --max_num_of_blocks=8192\n\t"
"It will simultaneously use 4 different true random generators\n\t"
"available on the web as the entropy source and HAVEGE RNG\n\t"
"as the additional input source to update the state of CSPRNG generator.\n\t"
"It's recommended to register at http://random.irb.hr/\n\t"
"and supply login credentials using environment variables\n\t"
"QRBG_USER=name and QRBG_PASSWD=password to enable\n\t"
"fast and high quality TRNG http://random.irb.hr/\n\t"
"Please note that daemon will stop sending data in the\n\t"
"case that internet connection will drop down or all\n\t"
"internet services used will become unusable.\n\n"

"Examples to measure the performance of the /dev/random device\n\n"

"time dd if=/dev/random count=8192 bs=8192 iflag=fullblock of=/dev/null\n\t"
"Test the reading speed from the /dev/random device. When csprngd\n\t"
" is running, reading speed of about 1MiB/s can be expected.\n\n"
"watch -n1 cat /proc/sys/kernel/random/entropy_avail\n\t"
"Watch remaining available entropy, update the display every second.\n\n"
"watch fuser -uvm /dev/random\n\t"
"Watch processes accessing /dev/random device\n\n"
"pkill -SIGUSR1 csprngd; time dd if=/dev/random count=8192 bs=8192 iflag=fullblock of=/dev/null; pkill -SIGUSR1 csprngd\n\t"
"SIGUSR1 signal will force (already running) csprngd process to output\n\t"
"the statistics information about the length of the bytes generated till now.\n\t"
"Use this code to test the performance of csprngd and kernel's random device.\n\t"
"It's also possible to deduct which portion of the entropy has been\n\t"
"provided by the csprngd.\n\n"
"watch -n1 -p \"dd if=/dev/random bs=64 count=1 of=/dev/null iflag=fullblock;\n"
"cat /proc/sys/kernel/random/entropy_avail\"\n\t"
"Read every second 64 Bytes from the /dev/random device and\n\t"
"print remaining available entropy in bits.\n\n"
"pv -L64 /dev/random > /dev/null\n\t"
"Read data from the /dev/random device with average speed of 64B/s\n\n"

;      

//}}}

//{{{ function minof((int n, ...)
long long int minof(int n, ...) {
  register int i;
  long long int min, a;
  va_list ap;

  va_start(ap, n);
  min = va_arg(ap, long long int);
  for(i = 1; i < n; i++) {
    a = va_arg(ap, long long int);
    if( min > a ) min = a;
  }

  va_end(ap);
  return min;
}
//}}}

//{{{ Arguments definition
#if GCC_VERSION > 40500
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
/* The options we understand. */
static struct argp_option options[] = {
  { 0,                                0,      0,  0,  UNDERLINE "Operation mode options" NORMAL },
  {"verbose",                       'v',      0,  0,  "Verbosity level. Two verbosity levels are supported. Second level (most verbose) is activated with \'-v -v\'" },
  {"foreground",                    603,      0,  0,  "Run in the foreground." },
  {"pidfile",                       'p', "file",  0,  "Path to the PID file for daemon mode." },
  {"no-fips",                       604,      0,  0,  "Turn off FIPS 140-2 random number tests validation. "
    "Default: only data passing FIPS 140-2 random number tests are sent to the kernel entropy pool."},
  {"write_statistics",              605,    "N",  0,  "Write statistics about the number of provided bytes & entropy "
    "and results of FIPS tests every \"N\" seconds. 0 to disable. Default: 3600s. Output of statistics can be forced anytime by sending SIGUSR1 signal." },
  { 0,                                0,      0,  0,  UNDERLINE "Cryptographically secure pseudo random number generator options" NORMAL},
  {"entropy_source",                801, "SOURCE",0,  "Specify SOURCE of RANDOM bytes for CTR_DRBG entropy input. "
                                                      "One of the following can be used: HAVEGE|SHA1_RNG|MT_RNG|HTTP_RNG|STDIN|EXTERNAL. "
                                                      "Please note that HTTP_RNG will retrieve random data from the web. It's recommended to register at "
                                                      "http://random.irb.hr/ and define login credentials using environment variables QRBG_USER=name and QRBG_PASSWD=password. "
                                                      "For HTTP_RNG consider using --derivation_function and --max_num_of_blocks=16384 or higher "
                                                      "to compensate for the low speed of the HTTP_RNG (approximately 200B/s). "
                                                      "Default: HAVEGE."},
  {"entropy_file",                  802, "FILE",  0,  "Use FILE as the source of the RANDOM bytes for CTR_DRBG entropy input. "
                                                      "It implies --entropy-source=EXTERNAL"},  
  { 0,                                0, 0,       0,  "" },
  {"derivation_function",           'd', 0,       0,  "Use DERIVATION FUNCTION. It will process entropy "
                                                      "and - when enabled - also additional input through DERIVATION FUNCTION "
                                                      "before reseed/change the state of CTR_DRBG. Default: DERIVATION FUNCTION is not used"},
  {"no-derivation_function",    'd'+OPP, 0, OPTION_HIDDEN,  "Do not use DERIVATION FUNCTION."},
  { 0,                                0, 0,       0,  "" },
  {"additional_source",              851,"SOURCE",0,  "Use additional input and specify the SOURCE of the RANDOM bytes for CTR_DRBG additional input. "
                                                      "One of the following can be used: NONE|HAVEGE|SHA1_RNG|MT_RNG|STDIN|EXTERNAL. "
                                                      "Please note that HTTP_RNG is not a good choice if you need to generate big amount of data. "
                                                      "It's recommended to use --entropy_source=HTTP_RNG instead. "
                                                      "Default: NONE (additional input is not used)."  },
  {"additional_file",                852, "FILE", 0,  "Use FILE as source of RANDOM bytes for CTR_DRBG additional_input. "
                                                      "It implies --additional_source=EXTERNAL." },
  { 0,                                0, 0,       0,  "" },
  {"max_num_of_blocks",             'm', "MAX",   0,  "Maximum number MAX of the CTR_DRBG blocks produced before reseed is performed. "
                                                      "Setting higher number will reduce the amount of entropy bytes needed. "
                                                      "Number of additional input bytes will be reduced only to max_num_of_blocks=4096. "
                                                      "Default: 512 blocks."},
  { 0,                                0, 0,       0,  "" },
  {"randomize_num_of_blks",       'r', 0, OPTION_HIDDEN,"Randomize number of CTR_DRBG blocks produced before reseed is performed. "
                                                      "When enabled, uniform random distribution [1,MAX] is used to get the number of generated CTR_DRBG blocks between reseeds. "
                                                      "When disabled, MAX of CTR_DRBG blocks is produced each time."},
  { 0,                                0, 0,       0,  "" },
  {"no-randomize_num_of_blks",  'r'+OPP, 0,       0,  "Produce MAX of CTR_DRBG blocks each time. "
                                                      "Default: uniform random distribution [1,MAX] is used to get the number of generated CTR_DRBG blocks between reseeds. "},
  { 0,                                0,      0,  0,  UNDERLINE "Output options" NORMAL },
  { "random-device",                'o', "file",  0,  "Kernel device used for entropy output. Default: /dev/random" },
  {"entropy_per_bit",               'e',    "N",  0,  "Entropy per bit of data written to the kernel entropy pool. Default 1.0. Allowed values 0.7<N<=1.0"},
  {"fill-interval",                 't',    "N",  0,  "When kernel entropy level is bigger than value specified at "
    "/proc/sys/kernel/random/write_wakeup_threshold\nthen write to the kernel random device "
    "every \"N\" seconds. 0 to disable. Default: 30s." },
  {"min_entropy",                   602,    "N",  0,  "Minimum number of entropy \"N\" written to the kernel random device at one time. Default: entropy 64. "
                                                      "(which is equal to 8 bytes when entropy_per_bit == 1." },
  {"upper_limit",                   'u',    "N",  0,  "Level \"N\" to which entropy level should be filled-up. "
    "\"N\" is the absolute number of bits or a percentage of the kernel pool size. "
	  "Default: 50%. Allowed range:\n0 <= N <=" UNDERLINE "<kernel random pool size>" NORMAL " or\n0% <= N <= 100%" },
  { 0,                                0, 0,       0,  UNDERLINE "HAVEGE parameters" NORMAL},
  {"havege_data_cache_size",        600, "SIZE",  0,  "CPU data cache SIZE in KiB. Default: auto detected." },
  {"havege_inst_cache_size",        601, "SIZE",  0,  "CPU instruction cache size in KiB. Default: auto detected." },
  { 0 }
};
#if GCC_VERSION > 40500
#pragma GCC diagnostic pop
#endif
/* Used by main to communicate with parse_opt. */
struct arguments {
  int verbose;                        //Verbosity level
  int foreground;                     //Run in a foreground or daemon mode?
  char *pidfile;                      //PID filename
  int pid_file_spec;                  //Was -p used? -p has no meaning when -f is specified.
  int fips_test;                      //Run fips tests?
  int derivation_function;            //Use DERIVATION FUNCTION?                         1=>true, 0=false
  int max_num_of_blocks;              //Maximum number MAX of CTR_DRBG blocks produced before reseed is performed
  int randomize_num_of_blocks;        //Randomize number of CTR_DRBG blocks produced before reseed is performed. 1=>true, 0=false
  int havege_data_cache_size;         //CPU data cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  int havege_inst_cache_size;         //CPU instruction cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  char *entropy_file;                 //Filename for entropy source (NULL means HAVEGE)
  char *add_input_file;               //Filename for additional input source (NULL means HAVEGE)
  double entropy_per_bit;             //Number in range (0,1>.
  int refill_interval;                //Refill interval in miliseconds (required by poll system call)
  int min_entropy;                    //Minimum number of entropy written to the kernel random device at one time
  int upper_limit;                    //Level to which entropy level should be refilled. Positive number is the absolute number of bits.
                                      //Negative number is the percentage of kernel entropy pool size as specified in file
                                      // /proc/sys/kernel/random/poolsize
  char *random_device;                //Kernel device used for entropy output
  long int write_statistics;          //Dump statistics at given time interval (seconds). 0 to disable. setitimer(2) requires long
  rand_source_type entropy_source;    //Source of entropy - HAVEGE, MT, EXTERNAL ?
  rand_source_type add_input_source;  //Source of additional input - HAVEGE, MT, EXTERNAL ?
  int entropy_source_set;             //Has been used option --entropy_source ?
  int additional_source_set;          //Has been used option --additional_source ?

};

static struct arguments arguments = {
  .verbose = 0,
  .foreground = 0,
  .pidfile = "/run/csprngd.pid",
  .pid_file_spec = 0,
  .fips_test = 1,
  .entropy_per_bit = 1.0,
  .derivation_function = 0,
  .max_num_of_blocks = 512,
  .randomize_num_of_blocks = 1,
  .havege_data_cache_size = 0,
  .havege_inst_cache_size = 0,
  .entropy_file = NULL,
  .add_input_file = NULL,
  .refill_interval = 30000,
  .min_entropy = 64,
  .upper_limit = -50,
  .random_device = "/dev/random",
  .write_statistics = 3600 ,
  .entropy_source = HAVEGE,
  .add_input_source = NONE,
  .entropy_source_set = 0,
  .additional_source_set = 0
}; 
//}}}

//{{{ Arguments parser
/* Parse a single option. */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

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
      long int n;
      long long int max = minof(2,  (long long int) INT_MAX,  (long long int) NIST_CTR_DRBG_MAX_NUMBER_OF_BITS_PER_REQUEST);
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n > max) )
       argp_error(state, "Maximum number of CTR_DRBG blocks produced before reseed is performed should be in range 1 - %lld", max);
      else
        arguments->max_num_of_blocks = n;
      break;
    }

    case 'r':
      arguments->randomize_num_of_blocks = 1;
      break;

    case 'r'+OPP:
      arguments->randomize_num_of_blocks = 0;
      break;

    case 603:
      arguments->foreground = 1;
      break;

    case 'p':
      arguments->pidfile = arg;
      arguments->pid_file_spec = 1;
      break;

    case 604:
      arguments->fips_test = 0;
      break;

    case 'e':{
      double d;
      char *p;
      d = strtod(arg, &p);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (d < 0.7) || (d > 1.0))
       argp_error(state, "Value N for --entropy_per_bit=N has to be in range 0.7 - 1.0.");
      else
        arguments->entropy_per_bit = d;
      break;
    }

    case 600:{
      long int n;
      char *p;
      long long int max = minof(2, (long long int) INT_MAX, (long long int) 16384);
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n > max) )
       argp_error(state, "CPU data cache SIZE in kiB for HAVEGE should be in range 1 - %lld.", max);
      else
        arguments->havege_data_cache_size= n;
      break;
    }

    case 601:{
      long int n;
      char *p;
      long long int max = minof(2,  (long long int) INT_MAX,  (long long int) 16384);
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n > max) )
       argp_error(state, "CPU instruction cache SIZE in KiB for HAVEGE should be in range 1 - %lld.", max);
      else
        arguments->havege_inst_cache_size = n;
      break;
    }

    case 'o':
      arguments->random_device = arg;
      break;

    case 't':{
      long int n;
      char *p;
      long int max = ( (long int) INT_MAX ) / 1000;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 0) || (n > max))
       argp_error(state, "--fill-interval has to be in range 0-%ld\n", max );
      else
        arguments->refill_interval = n * 1000;
      break;
    }

    case 605:{
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
    case 602:{
      long int n;
      char *p;
      long int max = 131072;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 0) || (n > max))
       argp_error(state, "Value N for --min_entropy=N has to be positive integer in range 0-%ld\n", max);
      else
        arguments->min_entropy = n;
      break;
    }

    case 'u':{
      long int n;
      char *p;
      long int max = 131072;
      n = strtol(arg, &p, 10);
      if ((p != arg) && (*p == '%')) {
        p++;
        if ((*p != 0) || (n < 0) || (n > 100))
          argp_error(state, "--upper_limit has to be in range 0-100%%.\n");
        else
          arguments->upper_limit = -n;
      } else {
        if ((p == arg) || (*p != 0) || (n > max))
          argp_error(state, "--upper_limit has to be in range 0-%ld B. Alternatively use syntax X%% "
              "where X is an integer and represents percentage of the kernel poolsize "
              "which can be checked at /proc/sys/kernel/random/poolsize\n", max);
        else
          arguments->upper_limit = n;
      }
      break;
    }

    case ARGP_KEY_ARG:
      argp_error(state, "No arguments are supported, only options\n");
      break;

    case ARGP_KEY_END:

      //{{{ Are entropy sources input options consistent?
      if ( arguments->entropy_source == EXTERNAL &&  arguments->entropy_file == NULL ) {
        argp_error(state, "Option --entropy_source=EXTERNAL requires option --entropy_file=FILE to be specified.\n");
      }

      if ( arguments->entropy_file != NULL && arguments->entropy_source_set != 0 &&  arguments->entropy_source != EXTERNAL ) {
         argp_error(state, "Option --entropy_source=%s is not compatible with option --entropy_file=%s.\n"
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
         argp_error(state, "Option --additional_source=%s is not compatible with option --additional_file=%s.\n"
             "Please note that in case when FILE source is intended then the option '--additional_source=EXTERNAL' can be omitted.\n",
             source_names[arguments->add_input_source], arguments->add_input_file);
      }

      if ( arguments->add_input_file != NULL && arguments->additional_source_set == 0 ) {
        arguments->add_input_source = EXTERNAL;
      }
      //}}}

      if (arguments->foreground) {
        if (arguments->pid_file_spec) {
          argp_error(state, "Argument -p cannot be used when -f argument is used.\n");
        }
      } else {
        if ( arguments->entropy_file != NULL ) {
          if ( arguments->entropy_file[0] != '/' ) {
            argp_error(state, "When running in the daemon mode entropy filename '%s' has to be absolute path.\n",  arguments->entropy_file);
          }
        }

        if ( arguments->add_input_file != NULL ) {
          if ( arguments->add_input_file[0] != '/' ) {
            argp_error(state, "When running in the daemon mode additional input filename '%s' has to be absolute path.\n",  arguments->add_input_file);
          }
        }
      }

      if (arguments->max_num_of_blocks == 1 && arguments->randomize_num_of_blocks) {
        argp_error(state, "When max_num_of_blocks == 1 there is no point to randomize number of blocks.\n"
           "Please either specify max_num_of_blocks to be >1 or disable randomization of number of blocks.\n");
      }

      if ( arguments->entropy_source == STDIN || arguments->add_input_source == STDIN ) {
        if ( isatty(fileno(stdin)) ) {
          if ( arguments->foreground == 0 ) {
          argp_error(state, "It's not supported to run the program in the daemon mode "
              "and read data from the terminal. Please either provide input of stdin to be pipe or regular file "
              "or run the program in the foreground.\n");
          } else {
            fprintf(stderr, "WARNING: Expecting STDIN input directly from the terminal. "
                "This is fairly unusual user case. Please consider using pipe or regular file as STDIN input.\n");
          }
        }
      }

      if ( arguments->write_statistics > 0  && ( arguments->entropy_source == HTTP_RNG || arguments->add_input_source == HTTP_RNG ) ) {
        if ( (double) HTTP_TIMEOUT_IN_SECONDS / (double) arguments->write_statistics > 0.05 ) {
          fprintf(stderr, "WARNING: HTTP source has been enabled. This can disrupt the frequency of statistics reports. "
              "HTTP can wait up to %d seconds before timing out. During this period, statistic output is suppressed.\n", HTTP_TIMEOUT_IN_SECONDS);
        }
      }

      if ( arguments->verbose > 2 ) {
        fprintf(stderr, "WARNING: Maximum verbosity level is 2. Verbosity level will be reduced from %d to 2.\n", arguments->verbose);
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
#pragma GCC diagnostic pop
#endif
//}}}

//{{{ void die(int exit_status)
void die(int exit_status) {
  fprintf( stderr, "ERROR: Exiting with status %d.\n", exit_status);
  exit(exit_status);
}
//}}}

//{{{ static void get_lock(const char* pidfile_name)
// Write our pid to our pidfile, and lock it
static void get_lock(const char* pidfile_name) {
  static FILE *daemon_lockfp = NULL;	/* Lockfile file pointer */
  static int daemon_lockfd;	        /* Lockfile file descriptor */

  int otherpid = 0;
  int r, return_status;

  assert(pidfile_name != NULL);

  if (!daemon_lockfp) {
    if (((daemon_lockfd = open(pidfile_name, O_RDWR|O_CREAT, 0644)) == -1)
        || ((daemon_lockfp = fdopen(daemon_lockfd, "r+"))) == NULL) {
      fprintf( stderr, "ERROR: Cannot open or create '%s': %s\n", pidfile_name, strerror(errno) );
      fprintf( stderr, "       See the option -p file.");
      die(EXIT_FAILURE);
    }
    fcntl(daemon_lockfd, F_SETFD, 1);

    do {
      r = flock(daemon_lockfd, LOCK_EX|LOCK_NB);
    } while (r && (errno == EINTR));

    if (r) {
      if (errno == EWOULDBLOCK) {
        rewind(daemon_lockfp);
        return_status = fscanf(daemon_lockfp, "%d", &otherpid);
        if ( return_status == 1 ) {
          fprintf(stderr, "ERROR: Cannot lock '%s', running daemon's pid may be %d\n", pidfile_name, otherpid);
        }
      } else {
        fprintf( stderr, "ERROR: can't lock '%s': %s\n", pidfile_name, strerror(errno) );
      }
      die(EXIT_FAILURE);
    }
  }

  rewind(daemon_lockfp);
  fprintf(daemon_lockfp, "%ld\n", (long int) getpid());
  fflush(daemon_lockfp);
  return_status = ftruncate(fileno(daemon_lockfp), ftell(daemon_lockfp));
  if ( return_status ) {
    fprintf( stderr, "ERROR: Cannot truncate pidfile '%s': %s\n", pidfile_name, strerror(errno) );
  }
}
//}}}

//{{{ void signal_record_sigterm(int signal)
void signal_record_sigterm(int signal) {
  gotsigterm = signal;
}
//}}}

//{{{ void signal_record_sigusr1(int signal)
void signal_record_sigusr1(int signal) {
  gotsigusr1 = signal;
}
//}}}

//{{{ Functions to redirect stdout/stderr to syslog
/*
SEE http://mischasan.wordpress.com/2011/05/25/redirecting-stderr-to-syslog/
Priority keywords are defined at /usr/include/sys/syslog.h
LOG_EMERG	0	system is unusable
LOG_ALERT	1	action must be taken immediately
LOG_CRIT	2	critical conditions
LOG_ERR	3	error conditions
LOG_WARNING	4	warning conditions
LOG_NOTICE	5	normal but significant condition
LOG_INFO	6	 informational
LOG_DEBUG	7	 debug-level messages
*/

static char const *priov[] = {
"EMERG:",   "ALERT:",  "CRIT:", "ERR:", "WARNING:", "NOTICE:", "INFO:", "DEBUG:"
};

//It will send data string to syslog. When data starts with one of string defined with *priov[]
//it will generate appropriate level. Otherwise LOG_INFO level will be used.
//NOTE: tolog(&stdout) will redirect fprintf(stdout, ...) to syslog but not printf()
static size_t writer(void *cookie, char const *data, size_t leng)
{
    (void)cookie;
    int     p = LOG_DEBUG, len;
    char *new;
    char *token;
    char *saveptr;
    unsigned int i, total_written;

    do len = strlen(priov[p]);
    while (memcmp(data, priov[p], len) && --p >= 0);

    if (p < 0) p = LOG_INFO;
    else data += len, leng -= len;
    while (*data == ' ') ++data, --leng;

    new = strndup(data, leng);
    if ( new == NULL ) {
      syslog(p, "%.*s", (int) leng, data);
      return leng;
    }

    //Replace \t with space. syslog will convert \t to #011 making the log file unreadable
    for (i=0; i<strlen(new); ++i) {
      if ( new[i]=='\t' ) new[i]=' ';
    }

    //Split string on new line
    //Syslog will print multi line messages on one line, making the output hard to read.
    token = strtok_r(new, "\n", &saveptr);
    total_written = 0;
    while(token != NULL)
    {
      i = strlen(token);
      total_written += i;
      syslog(p, "%.*s", i, token);
      token = strtok_r(NULL, "\n", &saveptr);
    }
    free(new);
    return total_written;
}

static int noop(void) {return 0;}
static cookie_io_functions_t log_fns = {
    (void*) noop, (void*) writer, (void*) noop, (void*) noop
};

void tolog(FILE **pfp)
{
    setvbuf(*pfp = fopencookie(NULL, "w", log_fns), NULL, _IOLBF, 0);
}
//}}}

//{{{ void print_statistics(uint64_t number_of_bytes, FILE *stream, struct timespec* start_time)
// Writes number_of_bytes in human readable form (using prefixes Ki, Mi) and throughput 
// number_of_bytes: value to print out
// stream:          where to write the output
// start_time:      Time when counter number_of_bytes was started         

void print_statistics(uint64_t number_of_bytes, FILE *stream, struct timespec* start_time) {

   long double throughput = 0.0L;
   int64_t time_milis;
   struct timespec current_time;
   static uint64_t previous_number_of_bytes = 0;
   static struct timespec previous_time = { 0, 0 };
   uint64_t diff;
   char output_string[200] = { 0 };
   unsigned int len = sizeof(output_string);
   unsigned int output_string_p = 0;

   clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &current_time);
   time_milis = elapsed_time( start_time, &current_time );
   fprintf(stream , "Total number of bytes sent to kernel's random device: %s\n", human_print_int(number_of_bytes) );
   if ( time_milis != 0 ) {
     throughput = (long double) number_of_bytes / (long double) time_milis * (long double) 1000.0;  //B/s
     output_string_p += snprintf(output_string, len, "Average throughput using cputime %s/s. ", human_print_ldouble ( throughput ) );
     assert(output_string_p<len);
   }
   //fprintf(stream, "start: %" PRIu64" s , %ld nanoseconds\n", (int64_t) start_time->tv_sec, start_time->tv_nsec);
   //fprintf(stream, "current: %" PRIu64" s , %ld nanoseconds\n", (int64_t) current_time.tv_sec, current_time.tv_nsec);


   //{{{ Bytes written and throughput since the last print
   if ( previous_number_of_bytes  && number_of_bytes >= previous_number_of_bytes) {
     diff = number_of_bytes - previous_number_of_bytes;
     output_string_p += snprintf(&output_string[output_string_p], len - output_string_p, "Bytes sent to kernel since the last print %s", 
         human_print_ldouble(diff) );
     assert(output_string_p<len);

     time_milis = elapsed_time( &previous_time, &current_time );
     if ( time_milis != 0 ) {
       throughput = (long double) diff / (long double) time_milis * (long double) 1000.0;  //B/s
       output_string_p += snprintf(&output_string[output_string_p], len - output_string_p,
           ", speed using cputime %s/s", human_print_ldouble( throughput ) ); 
       assert(output_string_p<len);
       assert(output_string_p == strlen(output_string));
     }
   }
   //}}}


   if ( output_string_p) fprintf(stream, "%s\n", output_string);
   previous_number_of_bytes = number_of_bytes;
   previous_time = current_time;

} 
//}}}

//{{{ int main(int argc, char **argv) 
int main(int argc, char **argv) {
  //{{{ Variables
  int exit_status = EXIT_SUCCESS;
  int is_daemon = 0 ;  //Will become true after we switch to daemon mode
  int fd;
  random_mode_t random_mode;
  int entropy[2];

  int return_code, bytes_generated, entropy_to_supply, bytes_to_write;
  uint64_t total_bytes_generated = 0;
  fips_state_type*   fips_state;
  mode_of_operation_type mode_of_operation;
  int output_buffer_size, bytes_needed;   //In bytes
  unsigned char* empty_data;
  struct rand_pool_info *rand_pool_info_pointer;

  struct rlimit rlim;
  int mlocked = 0;
  unsigned int mlock_limit;
  struct timespec start_time;
  struct itimerval alarm_value;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start_time);
  struct sigaction sigact;
  //}}}

  //{{{ Parse command line options 
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  //}}}

  //{{{ Close fd>2
  for(fd = 3; fd < 250; fd++) (void) close(fd);
  //}}}

  //{{{Init interface to kernel RANDOM device
  random_mode.random_device    = arguments.random_device;
  random_mode.refill_interval  = arguments.refill_interval;
  random_mode.entropy_per_bit  = arguments.entropy_per_bit;
  random_mode.min_entropy      = arguments.min_entropy;
  random_mode.upper_limit      = arguments.upper_limit;
  return_code = init_kernel_interface( &random_mode );
  if ( return_code < 0 ) {
    fprintf( stderr, "ERROR: init_kernel_interface has failed.\n");
    exit(EXIT_FAILURE);
  }
  //}}}

  //{{{ Go to daemon mode
  if (arguments.foreground == 0) {
    /* check if another csprngd daemon is running, 
     * create pidfile and lock it */
    get_lock(arguments.pidfile);

    //Can we allow daemon to redirect STDIN to /dev/null??
    if ( arguments.entropy_source == STDIN || arguments.add_input_source == STDIN) {
      //STDIN is being used. We cannot let daemon to redirect it to  /dev/null

      if (daemon(0, 1) < 0) {
        fprintf(stderr, "ERROR: Cannot daemonize: %s\n", strerror(errno) );
        return(EXIT_FAILURE);
      }
      fd = open ("/dev/null", O_RDWR, 0);
      if (fd < 0) { 
        fprintf (stderr, "ERROR: unable to open /dev/null: %s\n", strerror (errno) );
        die(EXIT_FAILURE);
      }
      if ( dup2(fd, STDOUT_FILENO) == -1 ) {
        fprintf (stderr, "ERROR: unable to redirect STDOUT to /dev/null: %s\n", strerror (errno) );
        die(EXIT_FAILURE);
      }

      if ( dup2(fd, STDERR_FILENO) == -1 ) {
        fprintf (stderr, "ERROR: unable to redirect STDERR to /dev/null: %s\n", strerror (errno) );
        die(EXIT_FAILURE);
      }

      if ( fd > 2 ) close (fd);
    } else {
      //STDIN is not being used. Let daemon redirect STDIN, STDOUT and STDERR to /dev/null

      if (daemon(0, 0) < 0) {
        fprintf(stderr, "ERROR: Cannot daemonize: %s\n", strerror(errno) );
        return(EXIT_FAILURE);
      }
    }

    openlog(PROGNAME, LOG_PID, LOG_DAEMON);
    tolog(&stderr);
    tolog(&stdout);
    is_daemon = 1;

    /* update pidfile */
    get_lock(arguments.pidfile);
  }
  //}}}

  //{{{ Print Summary
  if ( arguments.verbose ) {
    fprintf(stdout, "=============== %s SETUP ===============\n", PROGNAME);
    fprintf(stdout, "Running in foreground mode = %s\n",  arguments.foreground ? "yes" : "no");
    if ( arguments.foreground == 0 ) fprintf( stdout, "PID File location \'%s\'\n", arguments.pidfile);
    fprintf( stdout, "Kernel entropy pool-size %d bits.\n", random_mode.poolsize);
    fprintf( stdout, "Once filling the kernel entropy pool, we will try to fill entropy up to %d bits.\n", random_mode.upper_limit);
    fprintf( stdout, "When entropy level is greater than /proc/sys/kernel/random/write_wakeup_threshold value\n"
        "we will push at least %d bits of entropy to the kernel pool every %d miliseconds.\n", random_mode.min_entropy, random_mode.refill_interval);
    fprintf( stdout, "Detected /proc/sys/kernel/random/write_wakeup_threshold value to be %d bits.\n", random_mode.write_wakeup_threshold);
    fprintf( stdout, "Detected /proc/sys/kernel/random/read_wakeup_threshold value to be %d bits.\n", random_mode.read_wakeup_threshold);

    switch (random_mode.kernel_version) {
      case KERNEL_LINUX_24:
        fprintf( stdout, "Linux kernel version 2.4 was detected. Work-around for kernel's 4x entropy accounting bug will be applied.\n");
        break;
      case KERNEL_LINUX_26:
        fprintf( stdout, "Linux kernel version 2.6 or higher was detected.\n");
        break;
      default:
        fprintf( stdout, "Unrecognized linux kernel version.\n");
    }

    if ( arguments.entropy_source == EXTERNAL ) {
      fprintf (stderr, "ENTROPY SOURCE = File '%s'\n", arguments.entropy_file);
    } else {
      fprintf (stderr, "ENTROPY SOURCE = %s\n", source_names[arguments.entropy_source]);
    }

    fprintf( stdout, "USE ADDITIONAL INPUT = %s\n", (arguments.add_input_source != NONE ) ? "yes" : "no" );
    if ( arguments.add_input_source != NONE ) {
      if ( arguments.add_input_source == EXTERNAL ) {
        fprintf (stderr, "ADDITIONAL INPUT SOURCE = File '%s'\n", arguments.add_input_file);
      } else {
        fprintf (stderr, "ADDITIONAL INPUT SOURCE = %s\n", source_names[arguments.add_input_source]);
      }
    }

    fprintf( stdout, "USE DERIVATION FUNCTION = %s\n",
        arguments.derivation_function      ? "yes" : "no");

    fprintf( stdout, "MAXIMUM NUMBER OF CTR_DRBG BLOCKS PRODUCED BETWEEN RESEEDs = %d\n",
        arguments.max_num_of_blocks);
    fprintf( stdout, "RANDOMIZE NUMBER OF CTR_DRBG BLOCKS PRODUCED BETWEEN RESEEDs = %s\n",
        arguments.randomize_num_of_blocks  ? "yes" : "no");
        
    fprintf( stdout, "FIPS 140-2 VALIDATION = %s\n",
        arguments.fips_test                ? "yes" : "no");

    fprintf( stdout, "ENTROPY PER BIT = %g \n",
        arguments.entropy_per_bit );

    if (  arguments.entropy_source == HAVEGE || arguments.add_input_source == HAVEGE ) {
      if ( arguments.havege_data_cache_size ) {
        fprintf( stdout, "HAVEGE CPU data cache size = %d KiB\n", arguments.havege_data_cache_size);
      } else {
        fprintf( stdout, "HAVEGE CPU data cache size = AUTO DETECTED\n");
      }
      if ( arguments.havege_inst_cache_size ) {
        fprintf( stdout, "HAVEGE CPU instruction cache size = %d KiB\n", arguments.havege_inst_cache_size);
      } else {
        fprintf( stdout, "HAVEGE CPU instruction cache size = AUTO DETECTED\n");
      }
    }

    if ( arguments.write_statistics ) fprintf (stdout, "WRITE OUT STATISTICS EVERY = %ld seconds\n",  arguments.write_statistics);
    fprintf( stdout, "VERBOSE = %s, LEVEL = %d\n", 
        arguments.verbose                  ? "yes" : "no",
        arguments.verbose);

    fprintf (stdout, "===================================================================\n");
  }
  //}}}

  //{{{ Initialize CSPRNG
  //Size of CSPRNG buffer is at least random_mode.poolsize / random_mode.ent_count / 8 Bytes
  //(int) conversion act as floor on positive numbers. Add 0.5 to do the proper rounding
  output_buffer_size = (int) ( ( (double) random_mode.poolsize - 0.5 ) / ( random_mode.entropy_per_bit * 8.0 ) ) + 1;
  //Align buffer size on 8 Bytes boundary
  if (  output_buffer_size % 8 ) output_buffer_size += ( 8 - output_buffer_size % 8 );

  //fprintf( stdout,"Allocating %d bytes for rand_pool_info_pointer->buf\n", output_buffer_size);
  rand_pool_info_pointer = (struct rand_pool_info *) malloc ( sizeof(struct rand_pool_info) + output_buffer_size );
  if ( rand_pool_info_pointer == NULL ) {
    fprintf( stderr, "Dynamic memory allocation for rand_pool_info_pointer of size %zu has failed: %s\n", 
        sizeof(struct rand_pool_info) + output_buffer_size, strerror(errno) );
    die(EXIT_FAILURE);
  }

  //{{{ getrlimit
  if ( getrlimit(RLIMIT_MEMLOCK, &rlim) == 0 ) {
    mlock_limit = rlim.rlim_cur;
    //fprintf(stderr, "INFO:  getrlimit(RLIMIT_MEMLOCK, rlim) reports: current limit %d, maximum (ceiling) %d.\n", rlim.rlim_cur, rlim.rlim_max);
  } else {
    mlock_limit = 16384;
    fprintf (stderr, "WARNING: getrlimit(RLIMIT_MEMLOCK, rlim) has failed. Using %u as default limit. Reported error: %s\n", mlock_limit,  strerror (errno) );
  }
  //}}}

  if ( sizeof(struct rand_pool_info) + output_buffer_size <= mlock_limit ) {
    return_code = mlock( rand_pool_info_pointer,  sizeof(struct rand_pool_info) + output_buffer_size );
    if ( return_code != 0 && arguments.verbose ) {
      fprintf( stderr, "WARNING: cannot lock buffer to RAM (preventing that memory from being paged to the swap area)\n"
          "Size of buffer is %zu bytes: %s\n",  sizeof(struct rand_pool_info) + output_buffer_size, strerror(errno) );
    } else {
      mlocked = 1;
    }
  }

  //{{{ Entropy source and additional input source
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
  //}}}



  mode_of_operation.use_df                        = arguments.derivation_function;
  mode_of_operation.havege_debug_flags            = 0;
  mode_of_operation.havege_status_flag            = ( arguments.verbose == 2 ) ? 1 : 0;           
  mode_of_operation.havege_data_cache_size        = arguments.havege_data_cache_size; 
  mode_of_operation.havege_instruction_cache_size = arguments.havege_inst_cache_size;
  mode_of_operation.file_read_size                = 16384; 
  mode_of_operation.max_number_of_csprng_blocks   = arguments.max_num_of_blocks;
  mode_of_operation.random_length_of_csprng_generated_bytes = arguments.randomize_num_of_blocks;
  mode_of_operation.http_random_verbosity         = arguments.verbose; 

  fips_state = fips_approved_csprng_initialize(arguments.fips_test, 0, &mode_of_operation);
  if ( fips_state == NULL ) {
    fprintf( stderr, "ERROR: fips_approved_csprng_initialize has failed.\n");
    die(EXIT_FAILURE);
  }

  bytes_needed = output_buffer_size;
  empty_data = ( (unsigned char *) rand_pool_info_pointer->buf );

  //}}}

  //{{{ Check if we can send entropy to the kernel. Usually only root can do that.
  rand_pool_info_pointer->entropy_count = 0;
  rand_pool_info_pointer->buf_size = 0;
  if (ioctl(random_mode.dev_random_fd, RNDADDENTROPY, rand_pool_info_pointer) != 0) {
    fprintf( stderr, "ERROR: RNDADDENTROPY failed: %s\n", strerror(errno));
    if(geteuid() != 0) {
      fprintf( stderr, "ERROR: Program is not run with effective user ID set to root. Usually, root privileges are needed to send entropy to the kernel using ioctl RNDADDENTROPY call.\n");
    }
    die(EXIT_FAILURE);
  }
  //}}}  

  //{{{ Expected size of the entropy and additional input
  if ( arguments.verbose > 1 || arguments.entropy_source == HTTP_RNG || arguments.add_input_source == HTTP_RNG ) {
    uint64_t output_buffer_size = fips_state->raw_buf->total_size + fips_state->out_buf->total_size;
    long double target_rate = arguments.fips_test ? CSPRNG_RATE_WITH_FIPS : CSPRNG_RATE;
    csprng_estimate_bytes_needed ( fips_state->csprng_state, 1, 0, output_buffer_size,
        arguments.verbose, HTTP_REASONABLE_LENGTH, HTTP_RNG_RATE, target_rate);
  }
  //}}}

  //{{{ Instantiate fips_state
  return_code = fips_approved_csprng_instantiate ( fips_state ) ;
  if ( return_code ) {
    fprintf(stderr, "ERROR: fips_approved_csprng_instantiate has failed.\n");
    die(EXIT_FAILURE);
  }
  //}}}

//{{{ Signal handling
  sigemptyset( &sigact.sa_mask );
  sigact.sa_flags = 0;
  sigact.sa_handler = signal_record_sigterm;

  if ( sigaction(SIGINT,  &sigact, NULL) != 0 ) { fprintf(stderr, "ERROR: sigaction has failed.\n"); die(EXIT_FAILURE); }
  if ( sigaction(SIGTERM, &sigact, NULL) != 0 ) { fprintf(stderr, "ERROR: sigaction has failed.\n"); die(EXIT_FAILURE); }
  if ( sigaction(SIGPIPE, &sigact, NULL) != 0 ) { fprintf(stderr, "ERROR: sigaction has failed.\n"); die(EXIT_FAILURE); }

  sigact.sa_handler = signal_record_sigusr1;
  if ( sigaction(SIGUSR1, &sigact, NULL) != 0 ) { fprintf(stderr, "ERROR: sigaction has failed.\n"); die(EXIT_FAILURE); }
  if ( sigaction(SIGALRM, &sigact, NULL) != 0 ) { fprintf(stderr, "ERROR: sigaction has failed.\n"); die(EXIT_FAILURE); }
//}}}
 
  //{{{ Main loop
  if ( arguments.write_statistics ) {
    alarm_value.it_value.tv_sec = arguments.write_statistics;
    alarm_value.it_value.tv_usec = 0;
    alarm_value.it_interval.tv_sec = arguments.write_statistics;
    alarm_value.it_interval.tv_usec = 0;
    if ( setitimer(ITIMER_REAL, &alarm_value, NULL) ) {
      fprintf( stderr, "ERROR: setitimer failed: %s\n", strerror(errno));
      die(EXIT_FAILURE);
    }
  }

  while ( gotsigterm == 0 ) {
#if GENERATE_DATA_UPFRONT == 1
    bytes_generated = fips_approved_csprng_generate(fips_state, empty_data, bytes_needed );
    if ( bytes_generated < bytes_needed ) {
      fprintf( stderr, "ERROR: fips_approved_csprng_generate has returned %d bytes instead of %d bytes requested. "
          "Additional %d bytes are in the buffer.\n", bytes_generated, bytes_needed, rand_pool_info_pointer->buf_size );
      break;
    }
#endif

//{{{ How much entropy and bytes do we need ?   
    entropy_to_supply = wait_for_kernel_to_need_entropy(&random_mode);
    if ( gotsigterm ) break;

    if (entropy_to_supply<0  ) {
      fprintf( stderr, "ERROR: wait_for_kernel_to_need_entropy has failed.\n");
      die(EXIT_FAILURE);
    }
//}}}

    if ( entropy_to_supply > 0 ) {

      bytes_to_write = (int) ( ( (double) entropy_to_supply - 0.5 ) / ( random_mode.entropy_per_bit * 8.0 ) ) + 1;
      //fprintf(stdout, "entropy_to_supply = %d, \tbytes_to_write = %d\n", entropy_to_supply, bytes_to_write);
      //Align buffer size on 4 Bytes boundary
      if ( bytes_to_write % 4 ) bytes_to_write +=  ( 4 - bytes_to_write % 4 );

      rand_pool_info_pointer->entropy_count = entropy_to_supply;
      rand_pool_info_pointer->buf_size = bytes_to_write;
      /* Linux kernel 2.4 mode, account for 4x entropy accounting bug */
      if (random_mode.kernel_version == KERNEL_LINUX_24) {
        rand_pool_info_pointer->entropy_count /= 4;
      }
#if GENERATE_DATA_UPFRONT == 0

#if 1
      bytes_generated = fips_approved_csprng_generate(fips_state, empty_data, bytes_to_write );
#else
      //This is to test maximum throughput without fips_approved_csprng_generate overhead  
      bytes_generated =  bytes_to_write;
      memset( empty_data, 0, bytes_to_write);
#endif

      if ( bytes_generated < bytes_to_write ) {
        fprintf( stderr, "ERROR: fips_approved_csprng_generate has returned %d bytes instead of %d bytes requested.\n", 
            bytes_generated, bytes_to_write);
        break;
      }
#endif
      //{{{ Write random bytes to kernel
      if ( arguments.verbose == 2 ) {
        ioctl(random_mode.dev_random_fd, RNDGETENTCNT, &entropy[0]) ;
      }

      if (ioctl(random_mode.dev_random_fd, RNDADDENTROPY, rand_pool_info_pointer) != 0) {
        fprintf( stderr, "ERROR: RNDADDENTROPY failed: %s\n", strerror(errno));
        exit_status = EXIT_FAILURE;
        break;
      }
      if ( arguments.verbose == 2 ) {
        ioctl(random_mode.dev_random_fd, RNDGETENTCNT, &entropy[1]) ;
        fprintf( stdout, "Writing %4d bytes to kernel, with entropy %4d. Kernel entropy before %4d and after %4d, diff %4d. Real_diff - expected_diff %4d.\n",
            rand_pool_info_pointer->buf_size,
            rand_pool_info_pointer->entropy_count,
            entropy[0], entropy[1], entropy[1] - entropy[0], entropy[1] - entropy[0] - rand_pool_info_pointer->entropy_count);
      }
      total_bytes_generated += rand_pool_info_pointer->buf_size;
      //fprintf( stdout, "Total bytes written to kernel: \t%" PRIu64 "\n", total_bytes_generated);
      //}}}

#if GENERATE_DATA_UPFRONT == 1
      memmove( rand_pool_info_pointer->buf ,
          ( (char *) (rand_pool_info_pointer->buf) + rand_pool_info_pointer->buf_size) , output_buffer_size - rand_pool_info_pointer->buf_size);
      empty_data = (unsigned char *) (rand_pool_info_pointer->buf) + output_buffer_size - rand_pool_info_pointer->buf_size;
      bytes_needed = rand_pool_info_pointer->buf_size;
#endif

    }
     
    if ( gotsigusr1 ) {
      //if (arguments.write_statistics ) alarm(arguments.write_statistics);
      gotsigusr1 = 0;
      //fprintf ( stdout, "Total number of bytes sent to kernel's random device: \t%" PRIu64 "\n", total_bytes_generated);
      print_statistics(total_bytes_generated, stdout, &start_time);
      if ( arguments.fips_test) fprintf ( stdout, "%s", dump_fips_statistics ( &fips_state->fips_ctx.fips_statistics ) );
    }
  }

  //}}}

  //{{{ END of program - print final summary and do cleaning
  if ( gotsigterm ) fprintf ( stderr, "Received signal number %d\n", gotsigterm);

  //fprintf ( stdout, "Total number of bytes sent to kernel's random device: \t%" PRIu64 "\n", total_bytes_generated);
  print_statistics(total_bytes_generated, stdout, &start_time);
  if ( arguments.fips_test)  fprintf( stdout, "%s", dump_fips_statistics ( &fips_state->fips_ctx.fips_statistics ) );
  return_code = fips_approved_csprng_destroy(fips_state);
  if ( return_code ) {
    fprintf(stderr, "ERROR: fips_approved_csprng_destroy has failed.\n");
    exit_status = EXIT_FAILURE;
  }
  
  memset( rand_pool_info_pointer, 0, sizeof(struct rand_pool_info) + output_buffer_size );
  if ( mlocked ) munlock( rand_pool_info_pointer,  sizeof(struct rand_pool_info) + output_buffer_size );
  free(rand_pool_info_pointer);

  if ( is_daemon ) unlink(arguments.pidfile);

  return(exit_status);
  //}}}
}
//}}}
