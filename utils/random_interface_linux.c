/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

Interface to /dev/random device on Linux

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <sys/utsname.h>  //uname system call
#include <stdarg.h>
#include <errno.h>
#include <error.h>
#include <time.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

//TODO RHEL4 needs /usr/include/linux/types.h
#include <linux/types.h>
//
#include <linux/random.h>

#include <csprng/helper_utils.h>
#include "random_interface_linux.h"

//{{{ kernel_mode_t get_kernel_version( void )
//Get version of Linux kernel
kernel_mode_t get_kernel_version( void ) {
	struct utsname buf;
	long i;
	char *p, *q;

	if (uname(&buf))
		return KERNEL_UNSUPPORTED;

	if (!strncmp(buf.sysname, "Linux", 6)) {
		i = strtol(buf.release, &p, 10); /* Major version */
    //Kernel older than 2
		if ((i < 2) || *p != '.')
			return KERNEL_UNSUPPORTED;
    //Kernel 3 and newer
		if (i > 2)
			return KERNEL_LINUX_26;
    //Kernel 2
		p++;
		q = p;
		i = strtol(p, &q, 10);	/* Minor version */
		if (p == q || *q != '.' || i < 4)
			return KERNEL_UNSUPPORTED;
		if (i < 6)
			return KERNEL_LINUX_24;
		return KERNEL_LINUX_26;
	}
  //Not Linux
	return KERNEL_UNSUPPORTED;
}
//}}}

//{{{ int get_rng_poolsize(kernel_mode_t *kernel)
// Returns kernel random poolsize in bits by reading /proc/sys/kernel/random/poolsize
// See man -S4 random for details. In particualr, in kernel 2.4 value is in bytes, in kernel 2.6 value is in bits 
int get_rng_poolsize(kernel_mode_t *kernel)
{
   FILE *fp = NULL;
   int poolsize;
   int error = 0;

  fp = fopen("/proc/sys/kernel/random/poolsize", "r");
  if ( fp == NULL ) {
    fprintf(stderr, "ERROR: Cannot open /proc/sys/kernel/random/poolsize for reading: %s\n", strerror(errno) );
    error = 1;
  } else {
    if ( fscanf(fp, "%d", &poolsize) != 1) {
      fprintf(stderr, "ERROR: Cannot read /proc/sys/kernel/random/poolsize: %s\n", strerror(errno) );
      error = 1;
    }
    fclose(fp);
  }

  if ( *kernel == KERNEL_LINUX_24 ) {
    //In linux 2.4 poolsize is in bytes. In kernel 2.6, poolsize is in bits
    if (poolsize != 32 || 
        poolsize != 64 || 
        poolsize != 128 || 
        poolsize != 256 || 
        poolsize != 512 ||
        poolsize != 1024 ||
        poolsize != 2048) {
      fprintf(stderr, "ERROR: Kernel 2.4 was detected. In this kernel, "
          "valid sizes of random poolsize are 32, 64, 128, 256, 512, 1024, or 2048 Bytes. However, "
          "poolsize of %d was read from /proc/sys/kernel/random/poolsize\n", poolsize);
      error = 1;
    }
    poolsize *= 8;
  } else if ( *kernel == KERNEL_LINUX_26 ) {
    if (poolsize != 4096 ) {
      fprintf(stderr, "ERROR: Kernel 2.6 or newer was detected. In this kernel, "
          "valid size of random poolsize is 4096 bits. However, "
          "poolsize of %d was read from /proc/sys/kernel/random/poolsize\n", poolsize);
      error = 1;
    }
  } else {
      fprintf(stderr, "ERROR: Unknown kernel_mode_t was passed to get_rng_poolsize\n");
      error = 1;
  }
   if (error > 0) return -1;
   return poolsize;
}
//}}}

//{{{int get_proc_value(const char* file_name)
// Get value from /proc VFS. Designed for /proc/sys/kernel/random/{read_wakeup_threshold|write_wakeup_threshold}
int get_proc_value(const char* file_name)
{
   FILE *fp = NULL;
   int return_value;
   int return_status = 0;

  fp = fopen(file_name, "r");
  if ( fp == NULL ) {
    fprintf(stderr, "ERROR: Cannot open %s for reading: %s\n", file_name, strerror(errno) );
    return_status = 1;
  } else {
    if ( fscanf(fp, "%d", &return_value) != 1) {
      fprintf(stderr, "ERROR: Cannot read int value from %s: %s\n", file_name, strerror(errno) );
      return_status = 1;
    }
    fclose(fp);
  }
  if ( return_status ) return -1;
  return return_value;
}
//}}}

//{{{ int init_kernel_interface( random_mode_t* random_mode )
// Initialize the interface to the Linux Kernel entropy pool (/dev/random)
// Return -1 on ERROR, otherwise 0
// Following values are expected as input
// random_mode->random_device   : Random device, usually /dev/random
// random_mode->refill_interval : time in miliseconds to refill RANDOM DEVICE. 0 to disable
// random_mode->entropy_per_bit : entropy in one bit of RANDOM data. It's a number in interval (0.0 1.0>
// random_mode->min_entropy     : minimum entropy added in one RNDADDENTROPY operation
// random_mode->upper_limit     : level to which entropy level should be refilled. Positive number is the absolute number of bits.
//                                Negative number is the percentage of kernel entropy pool size as specified in file /proc/sys/kernel/random/poolsize

int init_kernel_interface( random_mode_t* random_mode )
{
  int changed = 0;

  //fd of /dev/random device
  random_mode->dev_random_fd = open(random_mode->random_device, O_RDWR);
  if (random_mode->dev_random_fd == -1) {
    fprintf(stderr, "ERROR: Cannnot open %s: %s\n", random_mode->random_device, strerror(errno) );
    return -1;
  }

  //Refill interval 
  if ( random_mode->refill_interval < 0 ) {
    fprintf(stderr, "ERROR: Expecting refill_interval to be >=0 but got %d!\n", random_mode->refill_interval);
    return -1;
  } 


  //OS kernel version - needed to correctly get pool size
  random_mode->kernel_version = get_kernel_version();
  if (random_mode->kernel_version == KERNEL_UNSUPPORTED) {
    fprintf(stderr, "ERROR: Unsupported linux kernel!\n");
    return -1;
  } 

  if ( random_mode->entropy_per_bit <= 0.0 || random_mode->entropy_per_bit > 1.0 ) {
    fprintf(stderr, "ERROR: Expecting entropy_per_bit to be >0.0 and <= 1.0 but got %g!\n", random_mode->entropy_per_bit);
    return -1;
  }

  //Size of /dev/random entropy pool. See /proc/sys/kernel/random/poolsize and man -S4 random
  //On kernel 2.6 and later default value is 4096 bits
  random_mode->poolsize = get_rng_poolsize(&random_mode->kernel_version);
  if ( random_mode->poolsize < 0 ) {
    fprintf(stderr, "ERROR: get_rng_poolsize has failed!\n");
    return -1;
  }

  if ( random_mode->min_entropy > random_mode->poolsize ||  random_mode->min_entropy < 1 ) {
    fprintf(stderr, "ERROR: Expecting min_entropy to be >0 and <= %d but got %d!\n", random_mode->poolsize, random_mode->min_entropy);
    return -1;
  }

  //Compute upper limit to which we would like to fill the kernel entropy pool. 
  //High values means that /dev/random will be dominated by csprng. Low values will hurt performance. 
  //It should be higher than /proc/sys/kernel/random/read_wakeup_threshold (64 bits) and
  ///proc/sys/kernel/random/write_wakeup_threshold (128 bits)
  //Zero values of arguments means that user input is in % of total pool size

  if ( random_mode->upper_limit == 0 ||  random_mode->upper_limit < -100 || random_mode->upper_limit > random_mode->poolsize ) {
    fprintf(stderr, "ERROR: Expecting upper_limit to be >0 and <= %d\n"
        "or >= -100 and < 0 (negative number represents percentage of kernel poolsize as specified in file /proc/sys/kernel/random/poolsize\n"
        "but got %d!\n", random_mode->poolsize, random_mode->upper_limit);
    return -1;
  }

  if ( random_mode->upper_limit < 0) {
    random_mode->upper_limit = (int) ( (double) ( random_mode->poolsize)  * (double) (-random_mode->upper_limit) / 100.0 );
  }

  random_mode->read_wakeup_threshold = get_proc_value("/proc/sys/kernel/random/read_wakeup_threshold");
  if ( random_mode->read_wakeup_threshold < 0 ) {
    fprintf(stderr, "ERROR: get_proc_value(\"/proc/sys/kernel/random/read_wakeup_threshold\") has failed!\n");
    return -1;
  }

  if ( random_mode->upper_limit <=  random_mode->read_wakeup_threshold ) {
    fprintf(stderr, "ERROR: random_mode->upper_limit should be bigger than "
        "\"/proc/sys/kernel/random/read_wakeup_threshold\" value of %d bits.\n", random_mode->read_wakeup_threshold);
    random_mode->upper_limit = random_mode->read_wakeup_threshold + 32;
    changed = 1;
  }


  random_mode->write_wakeup_threshold = get_proc_value("/proc/sys/kernel/random/write_wakeup_threshold");
  if ( random_mode->write_wakeup_threshold < 0 ) {
    fprintf(stderr, "ERROR: get_proc_value(\"/proc/sys/kernel/random/write_wakeup_threshold\") has failed!\n");
    return -1;
  }

  if ( random_mode->upper_limit <=  random_mode->write_wakeup_threshold ) {
    fprintf(stderr, "ERROR: random_mode->upper_limit should be bigger than "
        "\"/proc/sys/kernel/random/write_wakeup_threshold\" value of %d bits.\n", random_mode->write_wakeup_threshold);
    random_mode->upper_limit = random_mode->write_wakeup_threshold + 32;
    changed = 1;
  }


  if ( random_mode->upper_limit > random_mode->poolsize) {
    random_mode->upper_limit = random_mode->poolsize;
    changed = 1;
  }

  if ( changed ) {
    fprintf(stderr, "ERROR: Adjusting random_mode->upper_limit to %d bits.\n", random_mode->upper_limit);
  }
  return 0;
}
//}}}

//{{{int wait_for_kernel_to_need_entropy ( random_mode_t* random_mode )
//It will return -1 when error has occured. When no error has returned it will return entropy needed 
int wait_for_kernel_to_need_entropy ( random_mode_t* random_mode )
{
  int ent_count;
  struct pollfd pfd;
  int diff;
  
  pfd.fd = random_mode->dev_random_fd;
  pfd.events = POLLOUT; //Writing now will not block.

  struct timespec start, now;
  int64_t timeout_milisec;

  do { 
    //Get current entropy level
    if (ioctl(random_mode->dev_random_fd, RNDGETENTCNT, &ent_count) < 0) {
      fprintf(stderr, "ERROR: ioctl operation to get entropy count has failed: %s\n", strerror (errno) );
      return -1;
    } else if ( ent_count < random_mode->upper_limit || gotsigusr1 ) {
      diff = random_mode->upper_limit - ent_count;
      if ( diff < random_mode->min_entropy ) {
        if ( gotsigusr1 ) {
          return 0;
        } else {
          return random_mode->min_entropy;
        }
      } else {
        return diff;
      }
    }

    if (random_mode->refill_interval > 0) {
      timeout_milisec = random_mode->refill_interval;
      clock_gettime(CLOCK_MONOTONIC, &start);
      while ( gotsigterm == 0 && poll(&pfd, 1, timeout_milisec) < 0 ) {
        //The code will get to this section only if poll < 0 => an error has occured
        //or if poll == 0 => timeout
        //EFAULT The array given as argument was not contained in the calling program's address space.
        //EINTR  A signal occurred before any requested event; see signal(7).
        //EINVAL The nfds value exceeds the RLIMIT_NOFILE value.
        //ENOMEM There was no space to allocate file descriptor tables.
        if ( errno != EINTR ) {
          fprintf(stderr, "ERROR: poll failed: %s\n",  strerror (errno) );
          return -1;
        } else {
          //Signal caught. Check the remaining time to wait.
          if (  gotsigterm != 0 ) return 0;
          if (  gotsigusr1 != 0 ) break;
          clock_gettime(CLOCK_MONOTONIC, &now);
          timeout_milisec -= elapsed_time(&start, &now);
          start = now;
          if ( timeout_milisec < 0 ) break;
        }
      }
    } else {
      while ( gotsigterm == 0 &&  poll(&pfd, 1, -1) < 0 ) {
        if (errno != EINTR) {
          fprintf(stderr, "ERROR: poll failed: %s\n",  strerror (errno) );
          return -1;
        } else {
          if (  gotsigterm != 0 ) return 0;
          if (  gotsigusr1 != 0 ) break;
        }
      }
    }
  } while ( gotsigterm == 0 );

  return 0;

}
//}}}

