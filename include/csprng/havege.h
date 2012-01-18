/* vim:set ts=2 sw=2 sts=2 foldmethod=marker smarttab: */

/**
 ** Simple entropy harvester based upon the havege RNG
 **
 ** Copyright 2009-2011 Gary Wuertz gary@issiweb.com
 ** Copyright 2011 Jirka Hladky hladky DOT jiri AT gmail DOT com
 **
 ** This program is free software: you can redistribute it and/or modify
 ** it under the terms of the GNU General Public License as published by
 ** the Free Software Foundation, either version 3 of the License, or
 ** (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef HAVEGE_H
#define HAVEGE_H

/**
 * For a bit of portability
 */
//unsigned int produces slighlty faster code, thanks to ROR32 optimization. 
//On the other hand, using int data type seems to produce slightly better quality random numbers

//typedef unsigned int DATA_TYPE;
//typedef unsigned long LONG_DATA_TYPE;

typedef int DATA_TYPE;
typedef long LONG_DATA_TYPE;

/**
 * Configuration information
 */
#define HAVEGE_GENERIC_DCACHE 16
#define HAVEGE_GENERIC_ICACHE 16
#define HAVEGE_LOOP_CT 40

/**
 ** Hardware constraints
 */
#define HAVEGE_CRYPTOSIZECOLLECT 0x040000 /* 256k (1MB int)   */
#define HAVEGE_NDSIZECOLLECT     0x100000 /* 1M   (4MB int)   */
#define HAVEGE_NDSIZECOLLECTx2   0x200000 /* 2x NDSIZECOLLECT */
#define HAVEGE_MININITRAND       32

/**
 * Options flags
 */
#define VERBOSE         1
#define DEBUG_CPUID     2
#define DEBUG_LOOP      4
#define DEBUG_COMPILE   8
/**
 * Debugging definitions
 */
#define DEBUG_ENABLED(a) (info.havege_opts & a)!=0
#define DEBUG_OUT        printf
/**
 * Capture environment in an aggregate.
 */
struct hinfo {
  char  *arch;                  // machine architecture ("x86","sparc","ppc","ia64")
  char  *vendor;                // for x86 architecture only
  int   generic;                // idication for generic fallback
  int   i_cache;                // size of instruction cache in kb
  int   d_cache;                // size of data cache in kb
  int   loop_idx;               // loop index (1-max)
  int   loop_idxmax;            // max index for collection loop
  int   loop_sz;                // size of collection loop (bytes)
  int   loop_szmax;             // max size of collection loop (bytes)
  int   etime;                  // number of microseconds required by last collection
  int   havege_fills;           // number of times buffer has been filled
  int   havege_ndpt;            // get pointer
  int   havege_opts;            // option flags
  DATA_TYPE *havege_buf;        // the collection buffer
  //int   havege_max_pointer;     // Last element is at the position havege_bigarray[havege_max_pointer-1]
};
typedef struct hinfo *H_PTR;
typedef const struct hinfo *H_RDR;
/**
 * Public prototypes
 */
void           havege_debug(H_PTR hptr, char ** cpts, DATA_TYPE * pts);
int            havege_init(int icache, int dcache, int flags);
H_RDR          havege_state(void);
void           havege_status(char *buf, const int buf_size);
DATA_TYPE      ndrand();
const DATA_TYPE*     ndrand_remaining_buffer(unsigned int *size);
const DATA_TYPE*     ndrand_full_buffer();
#endif
