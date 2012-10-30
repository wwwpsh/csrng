/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

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

#include <csprng/helper_utils.h>
#include <stdio.h>
#include <string.h>

//{{{int elapsed_time(struct timespec *start, struct timespec *stop)Computes elapsed time in miliseconds
int64_t elapsed_time(struct timespec *start, struct timespec *stop)
{
  /*
  long int time;
  fprintf(stderr, "Start \t%d sec \t%d nsec\n", start->tv_sec, start->tv_nsec);
  fprintf(stderr, "Stop  \t%d sec \t%d nsec\n", stop->tv_sec, stop->tv_nsec);
  time = start->tv_sec;
  fprintf(stderr, "Start time: %s and %d nsec\n", ctime(&time), start->tv_nsec);
  time = stop->tv_sec;
  fprintf(stderr, "Stop time: %s and %d nsec\n", ctime(&time), stop->tv_nsec);
  */

  int64_t diff;
  diff = (stop->tv_sec - start->tv_sec) * 1000 + (stop->tv_nsec - start->tv_nsec) / 1000000;
  //fprintf(stderr, "Diff %" PRIu64" milis\n", diff);
  return diff > 0 ? diff : -diff;
}
//}}}

//{{{ uint64_t int_pow(uint64_t x, uint64_t p)
//Computes x^p
uint64_t int_pow(uint64_t x, uint64_t p)
{
  if (p == 0) return 1;
  if (p == 1) return x;

  uint64_t tmp = int_pow(x, p/2);
  if (p%2 == 0) return tmp * tmp;
  else return x * tmp * tmp;
}
//}}}

static const char *power_letter[] = {
  "",
  "Ki",  /* kibi */
  "Mi",  /* mebi */
  "Gi",  /* gibi */
  "Ti",  /* tebi */
  "Pi",  /* pebi */
  "Ei",  /* exbi */
  "Zi",  /* zebi 2**70 */
  "Yi"   /* yobi 2**80 */
};

const char* human_print_int (uint64_t number_of_bytes) {
  static char buf[64];
  int size = sizeof(buf);
  uint64_t integer_part = number_of_bytes;
  uint64_t remainder = number_of_bytes;
  long double human_bytes = 0;
  unsigned int human_bytes_index = 0;
  int ret;


  while ( integer_part >= 999 && human_bytes_index<8 ) {
    integer_part >>= 10;              //Same as divide by 2^10=1024
    ++human_bytes_index;
  }
  //integer_part in range 0 - 999 => this part is before decimal point

   if ( human_bytes_index > 0 ) {
      remainder %= (1 << human_bytes_index*10);         //remainder (after decimal point) 
      human_bytes = (long double) integer_part + (long double) (remainder)/ (long double) (int_pow(1024, human_bytes_index));
   } else {
      human_bytes = (long double) integer_part;
   }

   ret = snprintf(buf, size, "%7.3Lf %sB (%" PRIu64" B)", human_bytes, power_letter[human_bytes_index], number_of_bytes);
   buf[size-1] = 0;
   if ( ret < 1 || ret >= size ) fprintf(stderr, "WARNING: human_print_int: snprintf needs %d Bytes but only %d Bytes are available. Output is truncated.\n", ret+1,  size);
   return buf;
}

const char* human_print_ldouble (uint64_t number_of_bytes) {
  static char buf[16];
  int size = sizeof(buf);
  unsigned int human_bytes_index = 0;
  int ret;
  long double human_bytes = number_of_bytes;


  while ( human_bytes >= 999.0L && human_bytes_index<8 ) {
    human_bytes /= 1024.0L;
    ++human_bytes_index;
  }
  //integer_part in range 0 - 999 => this part is before decimal point

   ret = snprintf(buf, size, "%7.3Lf %sB", human_bytes, power_letter[human_bytes_index]);
   buf[size-1] = 0;
   if ( ret < 1 || ret >= size ) fprintf(stderr, "WARNING: human_print_ldouble: snprintf needs %d Bytes but only %d Bytes are available. Output is truncated.\n", ret+1,  size);
   return buf;
}

const char* human_print_ldouble_left_alligned (uint64_t number_of_bytes) {
  static char buf[16];
  int size = sizeof(buf);
  unsigned int human_bytes_index = 0;
  int ret;
  long double human_bytes = number_of_bytes;


  while ( human_bytes >= 999.0L && human_bytes_index<8 ) {
    human_bytes /= 1024.0L;
    ++human_bytes_index;
  }
  //integer_part in range 0 - 999 => this part is before decimal point

   ret = snprintf(buf, size, "%-5.1Lf %sB", human_bytes, power_letter[human_bytes_index]);
   buf[size-1] = 0;
   if ( ret < 1 || ret >= size ) fprintf(stderr, "WARNING: human_print_ldouble_left_alligned: snprintf needs %d Bytes but only %d Bytes are available. Output is truncated.\n", ret+1,  size);
   return buf;
}

