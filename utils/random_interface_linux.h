/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

Header file for routines which communicate with /dev/random device on Linux

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

#ifndef RANDOM_INTERFACE_LINUX_H
#define RANDOM_INTERFACE_LINUX_H
#include <signal.h>

extern volatile sig_atomic_t gotsigterm; /* SIGTERM/SIGINT => ==0 when no signal, ==1 when signal was received*/
extern volatile sig_atomic_t gotsigusr1; /* SIGUSR1 => ==0 when no signal, ==1 when signal was received*/

//{{{ Data structure to describe /dev/random

//Linux kernel version. We support version 2.4 (special handling) and all kernels from 2.6
typedef enum {
  KERNEL_UNSUPPORTED,
  KERNEL_LINUX_24,
  KERNEL_LINUX_26
} kernel_mode_t;

//Structure to describe /dev/random properties. See also /proc/sys/kernel/random VFS
typedef struct {
  char *random_device;               // Kernel device used for entropy output 
  int dev_random_fd;                 // File descriptor of kernel random device /dev/random
  int poolsize;                      // Kernel entropy pool size in bits
  int read_wakeup_threshold;         // /proc/sys/kernel/random/read_wakeup_threshold
  int write_wakeup_threshold;        // /proc/sys/kernel/random/write_wakeup_threshold
  int upper_limit;                   // To which level should daemon fill the enropy pool? Value in bits
  int min_entropy;                   // Minimum number of entropy to push to kernel entropy pool
  double entropy_per_bit;            // Entropy in one bit. Maximum number is 1.0
  kernel_mode_t kernel_version;      // Linux kernel version
  int refill_interval;               // How often should refill interval when we are above write_wakeup_threshold limit? 0 to disable.
} random_mode_t;
//}}}

//Get Linux kernel version 
kernel_mode_t get_kernel_version( void );

//Returns kernel random device poolsize in bits. It represents maximal entropy the kernel random device can hold
//Return value -1 represents an error condition
int get_rng_poolsize(kernel_mode_t *kernel);

//Get value from /proc VFS. Designed for /proc/sys/kernel/random/{read_wakeup_threshold|write_wakeup_threshold}
//Return value -1 represents an error condition
int get_proc_value(const char* file_name);

// Initialize the interface to the Linux Kernel entropy pool (/dev/random)
// Return -1 on ERROR, otherwise 0
// Following values are expected as input
// random_mode->random_device   : Random device, usually "/dev/random"
// random_mode->refill_interval : time in miliseconds to refill RANDOM DEVICE. 0 to disable
// random_mode->entropy_per_bit : entropy in one bit of RANDOM data. It's a number in interval (0.0 1.0>
// random_mode->min_entropy     : minimum entropy added in one RNDADDENTROPY operation
// random_mode->upper_limit     : level to which entropy level should be refilled. Positive number is the absolute number of bits.
//                                Negative number is the percentage of kernel entropy pool size as specified in file /proc/sys/kernel/random/poolsize
int init_kernel_interface( random_mode_t* random_mode );

//Wait for kernel until it needs entropy. It will return -1 when error has occured. When no error has returned it will return entropy needed.
int wait_for_kernel_to_need_entropy ( random_mode_t* random_mode );


#endif


