/*
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
*/

//{{{ includes
#include <stdlib.h>
#include <stdio.h>

#include <csprng/csprng.h>

#include <error.h>
#include <argp.h>
#include <string.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <poll.h>
//TODO RHEL4 needs /usr/include/linux/types.h
#include <linux/types.h>
//
#include <linux/random.h>
#include <syslog.h>
#include <fcntl.h>

#include "random_interface_linux.h"
#include "config.h"
//}}}

#define PROGNAME "csrngd"

const char *argp_program_version = "Version " VERSION "\nCopyright (c) 2011-2012 by Jirka Hladky";
const char *argp_program_bug_address =  "<" PACKAGE_BUGREPORT ">";
static char doc[] ="\33[1m\33[4mDaemon to feed entropy from cryptographically secure pseudorandom number generator to kernel entropy pool.\33[m";

//{{{ Arguments definition
/* The options we understand. */
static struct argp_option options[] = {
  { 0,                                0,      0,  0,  "\33[4mOperation mode options\33[m" },
  {"verbose",                       'v',      0,  0,  "Produce verbose output" },
  {"foreground",                    'f',      0,  0,  "Run in the foreground" },
  {"pidfile",                       'p', "file",  0,  "Path to the PID file for daemon mode" },
  {"no-fips",                       'g',      0,  0,  "Turn off FIPS 140-2 random number tests validation. "
    "Default: only data passing FIPS 140-2 random number tests are sent to the kernel entropy pool."},
  { 0,                                0,      0,  0,  "\33[4mCryptographically secure pseudorandom number generator options\33[m" },
  { 0,                                0,      0,  0,  "\33[4mOutput options\33[m" },
  { "random-device",                'o', "file",  0,  "Kernel device used for entropy output. Default: /dev/random" },
  {"entropy",                       'e',    "N",  0,  "Entropy per bit of data written to the kernel entropy pool. Default 1.0. Allowed values 0.7<N<=1.0"},
  {"fill-interval",                 't',    "N",  0,  "When kernel entropy level is bigger than value specified at "
    "/proc/sys/kernel/random/write_wakeup_threshold\nthen write to the kernel random device "
    "every \"N\" seconds. 0 to disable. Default: 30s." },
  {"min_entropy",                   'm',    "N",  0,  "Minimum number of entropy \"N\" written to the kernel random device at one time" },
  {"upper_limit",                   'u',    "N",  0,  "Level \"N\" to which entropy level should be filled-up. "
    "\"N\" is the absolute number of bits or a percentage of the kernel pool size. "
	  "Default: 50%. Allowed range 0 <= N <=\33[4m<kernel random pool size>\33[m or 0% <= N <= 100%" },
  { 0,                                0, 0,       0,  "\33[4mHAVEGE parameters:\33[m" },
  {"havege_data_cache_size",        600, "SIZE",  0,  "CPU data cache SIZE in KiB. Default: auto detected." },
  {"havege_inst_cache_size",        601, "SIZE",  0,  "CPU instruction cache size in KiB. Default: auto detected." },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments {
  int verbose;                  //Verbosity level
  int foreground;               //Run in a foreground or daemon mode?
  char *pidfile;                //PID filename
  int pid_file_spec;            //Was -p used? -p has no meaning when -f is specified.
  int fips_test;                //Run fips tests?
  int derivation_function;      //Use DERIVATION FUNCTION?                         1=>true, 0=false
  int additional_input;         //Use additional input for prediction resistance   1=>true, 0=false
  int max_num_of_blocks;        //Maximum number MAX of CTR_DRBG blocks produced before reseed is performed
  int randomize_num_of_blocks;  //Randomize number of CTR_DRBG blocks produced before reseed is performed. 1=>true, 0=false
  int havege_data_cache_size;   //CPU data cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  int havege_inst_cache_size;   //CPU instruction cache SIZE in KiB for HAVEGE. Default 0 (autodetected)
  double entropy_per_bit;       //Number in range (0,1>.
  int refill_interval;          //Refill interval in miliseconds (required by poll system call)
  int min_entropy;              //Minimum number of entropy written to the kernel random device at one time
  int upper_limit;              //Level to which entropy level should be refilled. Positive number is the absolute number of bits.
                                //Negative number is the percentage of kernel entropy pool size as specified in file
                                // /proc/sys/kernel/random/poolsize
  char *random_device;          //Kernel device used for entropy output
};

static struct arguments arguments = {
  .verbose = 0,
  .foreground = 0,
  .pidfile = "/run/csprngd.pid",
  .pid_file_spec = 0,
  .fips_test = 1,
  .entropy_per_bit = 1.0,
  .additional_input = 0,
  .derivation_function = 0,
  .max_num_of_blocks = 512,
  .randomize_num_of_blocks = 0,
  .havege_data_cache_size = 0,
  .havege_inst_cache_size = 0,
  .refill_interval = 30000,
  .min_entropy = 64,
  .upper_limit = -50,
  .random_device = "/dev/random",
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
      arguments->verbose = 1;
      break;
    case 'f':
      arguments->foreground = 1;
      break;
    case 'p':
      arguments->pidfile = arg;
      arguments->pid_file_spec = 1;
      break;
    case 'g':
      arguments->fips_test = 0;
      break;
    case 'e':{
      double d;
      char *p;
      d = strtod(arg, &p);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (d < 0.7) || (d > 1.0))
       argp_usage(state);
      else
        arguments->entropy_per_bit = d;
      break;
    }
    case 600:{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n >= INT_MAX) || ( n> 16384 ) )
       argp_error(state, "CPU data cache SIZE in kiB for HAVEGE should be in range 1 - %d.", 16384);
      else
        arguments->havege_data_cache_size= n;
      break;
    }
    case 601:{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 1) || (n >= INT_MAX) || ( n> 16384 ) )
       argp_error(state, "CPU instruction cache SIZE in KiB for HAVEGE should be in range 1 - %d.", 16384);
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
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 0) || (n >= INT_MAX/1000))
       argp_usage(state);
      else
        arguments->refill_interval = n * 1000;
      break;
    }
    case 'm':{
      long int n;
      char *p;
      n = strtol(arg, &p, 10);
      if ((p == arg) || (*p != 0) || errno == ERANGE || (n < 0) || (n >= INT_MAX/1000))
       argp_usage(state);
      else
        arguments->min_entropy = n;
      break;
    }
    case 'u':{
     long int n;
     char *p;
     n = strtol(arg, &p, 10);
     if ((p != arg) && (*p == '%')) {
       p++;
       if ((*p != 0) || (n < 0) || (n > 100))
         argp_usage(state);
       else
         arguments->upper_limit = -n;
     } else {
       if ((p == arg) || (*p != 0) || (n >= 131072))
         argp_usage(state);
       else
         arguments->upper_limit = n;
     }
     break;
    }
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, 0, doc };
//}}}

//{{{ void die(int is_daemon, int exit_status)
void die(int is_daemon, int exit_status) {
  if (is_daemon) syslog(LOG_ERR, "Exiting with status %d...", exit_status);
  exit(exit_status);
}
//}}}

//{{{ static void get_lock(const char* pidfile_name)
// Write our pid to our pidfile, and lock it
static void get_lock(int is_daemon, const char* pidfile_name) {
  static FILE *daemon_lockfp = NULL;	/* Lockfile file pointer */
  static int daemon_lockfd;	        /* Lockfile file descriptor */

  int otherpid = 0;
  int r, return_status;

  assert(pidfile_name != NULL);

  if (!daemon_lockfp) {
    if (((daemon_lockfd = open(pidfile_name, O_RDWR|O_CREAT, 0644)) == -1)
        || ((daemon_lockfp = fdopen(daemon_lockfd, "r+"))) == NULL) {
      message_strerr(is_daemon, LOG_ERR, errno, "Cannot open or create %s", 
          pidfile_name);
      die(is_daemon, EXIT_FAILURE);
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
          message(is_daemon, LOG_ERR,
              "Cannot lock %s, running daemon's pid may be %d",
              pidfile_name, otherpid);
        }
      } else {
        message_strerr(is_daemon, LOG_ERR, errno,
            "can't lock %s", pidfile_name);
      }
      die(is_daemon, EXIT_FAILURE);
    }
  }

  rewind(daemon_lockfp);
  fprintf(daemon_lockfp, "%ld\n", (long int) getpid());
  fflush(daemon_lockfp);
  return_status = ftruncate(fileno(daemon_lockfp), ftell(daemon_lockfp));
  if ( return_status ) {
    message_strerr(is_daemon, LOG_ERR, errno, "Cannot truncate pidfile %s", pidfile_name);
  }
}
//}}}

//{{{int elapsed_time(struct timespec *start, struct timespec *stop)Computes elapsed time in miliseconds
int elapsed_time(struct timespec *start, struct timespec *stop)
{
        int diff;
        diff = (stop->tv_sec - start->tv_sec) * 1000 + (stop->tv_nsec - start->tv_nsec) / 1000000;
        return abs(diff);
}
//}}}

//{{{ int main(int argc, char **argv) 
int main(int argc, char **argv) {
  int exit_status = EXIT_SUCCESS;
  int is_daemon = 0 ;  //Will become true after we switch to daemon mode
  int fd;
  random_mode_t random_mode;

  int return_code, bytes_generated, entropy_to_supply, bytes_to_write;
  csprng_state_type csprng_state;
  fips_state_type   fips_state;
  mode_of_operation_type mode_of_operation;
  unsigned char *output_buffer;
  int output_buffer_size, bytes_needed;   //In bytes
  char* empty_data;
  struct rand_pool_info *rand_pool_info_pointer;
   
  argp_parse(&argp, argc, argv, 0, 0, &arguments);
  if (arguments.foreground) {
    if (arguments.pid_file_spec) {
      fprintf(stderr,"Argument -p is ignored when -f argument is used.\n");
    }
  }

  //Close fd>2
  for(fd = 3; fd < 250; fd++) (void) close(fd);

  //Init interface to kernel RANDOM device
  random_mode.random_device    = arguments.random_device;
  random_mode.refill_interval  = arguments.refill_interval;
  random_mode.entropy_per_bit  = arguments.entropy_per_bit;
  random_mode.min_entropy      = arguments.min_entropy;
  random_mode.upper_limit      = arguments.upper_limit;
  return_code = init_kernel_interface( &random_mode );
  if ( return_code < 0 ) {
    fprintf(stderr, "ERROR: init_kernel_interface has failed\n");
    exit(EXIT_FAILURE);
  }

  //Print Summary
  if ( arguments.verbose ) {
    fprintf(stderr, "Kernel entropy poolsize %d bits.\n", random_mode.poolsize);
    fprintf(stderr, "Once filling the kernel entropy pool, we will try to fill entropy upto %d bits.\n", random_mode.upper_limit);
    fprintf(stderr, "When entropy level is greater than /proc/sys/kernel/random/write_wakeup_threshold value\n"
        "we will push at least %d bits of entropy to the kernel pool every %d miliseconds.\n", random_mode.min_entropy, random_mode.refill_interval);
    fprintf(stderr, "Detected /proc/sys/kernel/random/write_wakeup_threshold value to be %d bits.\n", random_mode.write_wakeup_threshold);
    fprintf(stderr, "Detected /proc/sys/kernel/random/read_wakeup_threshold value to be %d bits.\n", random_mode.read_wakeup_threshold);

    switch (random_mode.kernel_version) {
      case KERNEL_LINUX_24:
        fprintf(stderr, "Linux kernel version 2.4 was detected.\n");
        break;
      case KERNEL_LINUX_26:
        fprintf(stderr, "Linux kernel version 2.6 or higher was detected.\n");
        break;
      default:
        fprintf(stderr, "Unrecognized linux kernel version\n");
    }
  }

  //{{{ Initialize CSPRNG
  //Size of CSPRNG buffer is at least random_mode.poolsize / random_mode.ent_count / 8 Bytes
  //(int) conversion act as floor on positive numbers. Add 0.5 to do the proper rounding
  output_buffer_size = (int) ( ( (double) random_mode.poolsize - 0.5 ) / ( random_mode.entropy_per_bit * 8.0 ) ) + 1;
  //Allign buffer size on 8 Bytes boundary
  if (  output_buffer_size % 8 ) output_buffer_size += ( 8 - output_buffer_size % 8 );
  assert( output_buffer_size % 8 == 0);
  if ( arguments.verbose ) {
    message(is_daemon, LOG_INFO,"Allocating %d Bytes for rand_pool_info_pointer->buf", output_buffer_size);
  }
  
  rand_pool_info_pointer = (struct rand_pool_info *) malloc ( sizeof(struct rand_pool_info) + output_buffer_size );
  if ( rand_pool_info_pointer == NULL ) {
    message_strerr(is_daemon, LOG_ERR, errno,"Dynamic memory allocation for rand_pool_info_pointer of size %d has failed\n", sizeof(struct rand_pool_info) + output_buffer_size);
    die(is_daemon, EXIT_FAILURE);
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
    message_strerr(is_daemon, LOG_ERR, errno, "ERROR: fips_approved_csprng_init has returned %d\n",return_code);
    die(is_daemon, EXIT_FAILURE);
  }

  bytes_needed = output_buffer_size;
  empty_data = ( (char *) rand_pool_info_pointer->buf );

  //}}}
 
  //{{{ Go to daemon mode
  if (arguments.foreground == 0) {
    /* check if another csprngd daemon is running, 
     * create pidfile and lock it */
    get_lock(is_daemon, arguments.pidfile);

    if (daemon(0, 0) < 0) {
      message_strerr(is_daemon, LOG_ERR, errno, "Cannot daemonize");
      return(EXIT_FAILURE);
    }

    openlog(PROGNAME, LOG_PID, LOG_DAEMON);
    is_daemon = 1;

    /* update pidfile */
    get_lock(is_daemon, arguments.pidfile);
  }
  //}}}

  //{{{ Main loop
  for (;;) {

    bytes_generated = fips_approved_csprng_generate(&fips_state, empty_data, bytes_needed );
    if ( bytes_generated < bytes_needed ) {
      message (is_daemon, LOG_ERR, "ERROR: fips_approved_csprng_generate has returned %d Bytes instead of %d Bytes requested.\n", 
          bytes_generated, bytes_to_write);
      break;

    entropy_to_supply = wait_for_kernel_to_need_entropy(is_daemon, &random_mode);
    if (entropy_to_supply<0  ) {
      message_strerr(is_daemon, LOG_ERR, errno, "ERROR: wait_for_kernel_to_need_entropy has returned %d\n",return_code);
      die(is_daemon, EXIT_FAILURE);
    }
    bytes_to_write = (int) ( ( (double) entropy_to_supply - 0.5 ) / ( random_mode.entropy_per_bit * 8.0 ) ) + 1;
    //Allign buffer size on 4 Bytes boundary
    if ( bytes_to_write % 4 ) bytes_to_write +=  ( 4 - bytes_to_write % 4 );
    assert( output_buffer_size % 4 == 0);
    assert( bytes_to_write<=bytes_generated);  //TODO

    //printf("%d %d\n", entropy_to_supply, bytes_to_write);
    //sleep (2);
    //

    rand_pool_info_pointer->entropy_count = entropy_to_supply;
    rand_pool_info_pointer->buf_size = bytes_to_write;
    /* Linux kernel 2.4 mode, account for 4x entropy accounting bug */
    if (random_mode.kernel_version == KERNEL_LINUX_24) {
      entropy.ent_count /= 4;
    }


    //ioctl(random_mode.dev_random_fd, RNDGETENTCNT, &bytes_generated) ;
    //printf("Before %d \t", bytes_generated);

    if (ioctl(random_mode.dev_random_fd, RNDADDENTROPY, rand_pool_info_pointer) != 0) {
      message_strerr(is_daemon, LOG_ERR, errno, "RNDADDENTROPY failed");
      exit_status = EXIT_FAILURE;
      break;
    }

    memmove( rand_pool_info_pointer->buf , ( (char *) (rand_pool_info_pointer->buf) + rand_pool_info_pointer->buf_size) , output_buffer_size - rand_pool_info_pointer->buf_size);
    empty_data = ( (char *) (rand_pool_info_pointer->buf) + rand_pool_info_pointer->buf_size) + output_buffer_size - rand_pool_info_pointer->buf_size;

    //ioctl(random_mode.dev_random_fd, RNDGETENTCNT, &bytes_generated );
    //printf("After %d \n", bytes_generated);
    
  }

  //}}}
  
  return_code = fips_approved_csprng_destroy(&fips_state);
  if ( return_code ) {
    error(EXIT_FAILURE, errno, "ERROR: fips_approved_csprng_destroy has returned %d\n",return_code);
    exit_status = EXIT_FAILURE;
  }

  free(rand_pool_info_pointer);

  return(exit_status);
}
//}}}


#if 0
static void random_add_entropy(void *buf, size_t size)
{
	struct {
		int ent_count;
		int size;
		unsigned char data[size];
	} entropy;

	assert(buf != NULL);

	entropy.ent_count = (int)(arguments->rng_entropy * size * 8);
	/* Linux kernel 2.4 mode, account for 4x entropy accounting bug */
	if (kernel == KERNEL_LINUX_24) entropy.ent_count /= 4;

	entropy.size = size;
	memcpy(entropy.data, buf, size);
	
	if (ioctl(random_fd, RNDADDENTROPY, &entropy) != 0) {
		message_strerr(is_daemon, LOG_ERR, errno, "RNDADDENTROPY failed");
		exitstatus = EXIT_FAILURE;
	}

	memset(entropy.data, 0, size);

	//rng_stats.bytes_sent += size;
	//rng_stats.entropy_sent += entropy.ent_count;
}

static void run_daemon(H_PTR handle)
{
   int poolsize;

   poolsize = get_poolsize();
   if (0 == params->run_level) {
      unsigned int  nbytes = (unsigned)poolsize/8;
      unsigned int  buf[(nbytes+sizeof(int)-1)/sizeof(int)];
      char rb[sizeof(struct rand_pool_info)+nbytes+2];
      
      exec_daemon(handle, poolsize,(struct rand_pool_info *)rb,buf);
      }
   else get_info(handle);
}

/* add entropy to char device "/dev/random" 
*/
int add_entropy(void) {
  struct rand_pool_info *t;
  int fd, ret = 0;

  poly_substition(u16_rbytes, KEY);
  convert_stoi(rbytes, u16_rbytes);

  printf("[+] Adding 0x%-8x 0x%-8x ... 0x%-8x",
	 rbytes[1], rbytes[2], rbytes[MAX_RBYTES / 2 - 1]);

  t = (struct rand_pool_info *) malloc(sizeof(struct rand_pool_info) +
				       MAX_RBYTES / 2);
  t->entropy_count = MAX_RBYTES / 2;
  t->buf_size = MAX_RBYTES / 2;

  memcpy(&(t->buf[0]), rbytes, MAX_RBYTES / 2);


  if ( (fd = open(RANDOM_DEVICE, O_WRONLY)) < 0) {
    printf("\n[-] cannot open RANDOM_DEVICE.\n");
    exit(1);
  }

  /* RANDOM_DEVICE is now opened, run ioctl() */
  if (ioctl(fd, RNDADDENTROPY, t) < 0) {
    printf("\n[-] cannot ioctl on RANDOM_DEVICE. Are you root ?\n");
    exit(1);
  }

  close(fd);

  return ret;
}

#endif
