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
 **
 ** This source is an adaptation of work released as
 **
 ** Copyright (C) 2006 - André Seznec - Olivier Rochecouste
 **
 ** under version 2.1 of the GNU Lesser General Public License
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>
#include <csprng/havege.h>

//TODO - get rid of global variables

/**
 ** Microsecond resolution times use gettimeofday
 */
#define MSC_DATA          static struct timeval et0,et1;
#define MSC_ELAPSED()     (et1.tv_sec - et0.tv_sec)*1000000 + et1.tv_usec - et0.tv_usec
#define MSC_START()       gettimeofday(&et0,NULL)
#define MSC_STOP()        gettimeofday(&et1,NULL)

/**
 ** Compiler intrinsics are used to make the build more portable and stable
 ** with fallbacks provided where the intrisics cannot be used. 
 */

/**
 * State
 */
static struct  hinfo info;                               // configuration
MSC_DATA;

/*{{{ GCC */
#ifdef __GNUC__
/* ################################################################################# */

/**
 ** For the GNU compiler, the use of a cpuid intrinsic is somewhat garbled by the
 ** fact that some distributions (Centos 5.x) carry an empty cpuid.h (in order
 ** to back patch glicb?). AFAIK cpuid did not appear in gcc until version 4.3
 ** although it was in existance before. If we do not have a valid cpuid.h,
 ** we provide our own copy of the file (from gcc 4.3)
 **
 ** Also, gcc 4.4 and later provide an optimize attribute which remedies the
 ** effect ever increasing optimization on the collection loop
 */
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100  +  __GNUC_PATCHLEVEL__)

#define ASM __asm__ volatile
/**
 ** The collection mechanism cannot withstand agressive optimization
 */
#if GCC_VERSION>=40400
DATA_TYPE havege_collect(volatile H_PTR hptr) __attribute__((optimize(1)));
#endif
/**
 ** For the intel world...
 */
#ifdef HAVE_ISA_X86
#define ARCH "x86"

#if GCC_VERSION<40300
#undef HAVE_CPUID_H
#endif
#ifdef HAVE_CPUID_H
#include <cpuid.h>
#else
#include "cpuid-43.h"
#endif

/**
 ** Compatability wrappers
 */
#define CPUID(level,p)\
  {\
  __cpuid_count (level,p[3],p[0],p[1],p[2],p[3]);\
  }
#define HASCPUID(p) __get_cpuid_max(0, p)
/**
 ** The rdtsc intrinsic is called in by x86intrin.h - also a recent gcc innovation
 ** There have been some discussions of the code in 4.5 and 4.6, so you may opt
 ** to use the inline alternative based on GCC_VERSION
 */
#ifdef HAVE_X86INTRIN_H
#include <x86intrin.h>
#define HARDCLOCK(x) x=__rdtsc()
#else
#define HARDCLOCK(x) ASM("rdtsc;movl %%eax,%0":"=m"(x)::"ax","dx")
//#define HARDCLOCK(x) x=3
#endif
#else
/**
 * No cpuid support outside of the x86 family
 */
#define CPUID(level,p) 0
#define HASCPUID(p)    0

#ifdef HAVE_ISA_SPARC
#define ARCH "sparc"
#define HARDCLOCK(x) ASM("rd %%tick, %0":"=r"(x):"r"(x))
#endif

#ifdef HAVE_ISA_SPARCLITE
#define ARCH "sparclite"
#define HARDCLOCK(x) ASM(".byte 0x83, 0x41, 0x00, 0x00");\
  ASM("mov   %%g1, %0" : "=r"(x))
#endif

#ifdef HAVE_ISA_PPC
#define ARCH "ppc"
#define HARDCLOCK(x) ASM("mftb %0":"=r"(x)) /* eq. to mftb %0, 268 */
#endif

#ifdef HAVE_ISA_IA64
#define ARCH "ia64"
#define CPUID(op,reg) ASM("mov %0=cpuid[%1]"\
   : "=r" (value)\
   : "r" (reg))
#define HARDCLOCK(x) ASM("mov %0=ar.itc" : "=r"(x))
#define HASCPUID(x) x=1
#endif
#endif
/**
 *  Use the "&&" extension to calculate the LOOP_PT
 */
#define CODE_PT(a)   a
#define LOOP_PT(a)   &&loop##a
/* ################################################################################# */
#endif

/*}}}*/

/*{{{ MSVC*/
/**
 * For the MSVC world
 */
#if _MSVC_VERS
/* ################################################################################# */
#define ARCH "x86"
/**
 * For the MSVC compilers V8 and above
 */
#include <intrin.h>
/**
 * Read the processor timestamp counter
 */
#define HARDCLOCK(x) x=__rdtsc()
/**
 * Normalize to the gcc interface
 */
#define CPUID(level,p) return __cpuidx(p, p[3], level)
#define HASCPUID(p) \
{
  CPUID(0,a,b,c,d)
}  
/**
 * Use the __ReturnAddress intrisic to calculate the LOOP_PT
 */
#define CODE_PT(a) __ReturnAddress()
#define LOOP_PT(a) 0
#endif
/* ################################################################################# */
/*}}}*/

/*{{{ cache_configure function */
#ifdef CPUID
/**
 * Wrapper around the cpuid macro to assist in debugging
 */
static void cpuid(int fn, unsigned int *p, char * tag)
{
  CPUID(fn,p);
  if (DEBUG_ENABLED(DEBUG_CPUID)) {
    char *rn = "ABDC";
    char d[sizeof(int)+1];int i,j;

    DEBUG_OUT("%s:%d\n",tag,fn);
    for (i=0;i<4;i++) {
      int t = p[i];
      int c = 0;
      for (j=sizeof(unsigned int);j>=0;j--) {
        d[j] = (char)c;
        c = t&0xff;
        if (!isprint(c)) c = '.';
        t >>= 8;
      }
      DEBUG_OUT("E%cX %10x %s\n", rn[i], p[i], d);
    }
  }
}

/**
 * Automatic configuration for amd
 *
 * As per AMD document 2541, April 2008
 */
static int configure_amd(void)
{
   unsigned char regs[4*sizeof(int)];
   unsigned int *p = (unsigned int *)regs;

   cpuid(0x80000000,p,"configure_amd");
   if ((p[0]&15)>=5) {                       // We want the L1 info
      cpuid(0x80000005,p,"configure_amd");
      info.d_cache   =  (p[2]>>24) & 0xff;   // l1 data cache
      info.i_cache   =  (p[3]>>24) & 0xff;   // l1 instruction cache
      return 1;
      }
   return 0;
}
/**
 * Automatic configuration for Intel x86 chips
 *
 * Notes: The "pentium hack" is to use the trace cache size for the instruction cache
 *        if no instruction cache value is found.
 *
 *        Recent Intel processor handbooks, hint that a processor may return a
 *        cache descriptor of 0xff to say in effect "buzz-off use leaf 4". My
 *        limited testing with leaf 4 indicates that it does not return the
 *        same information as leaf 2 - so in this code leaf 4 is only used as
 *        a fallback....
 */
static int configure_intel(unsigned int lsfn)
{
   unsigned char regs[4*sizeof(int)];
   unsigned int *p = (unsigned int *)regs;
  /**
   * As per Intel application note 485, August 2009 the following table contains
   * triples descriptor#, type (0=instruction,1=data), size (kb)
   * This table contains only L1 instruction(0), data(1), and trace(2) items.
   */
   static const int desc[] = {
      0x06, 0,  8 , // 4-way set assoc, 32 byte line size
      0x08, 0, 16 , // 4-way set assoc, 32 byte line size
      0x09, 0, 32 , // 4-way set assoc, 64 byte line size +
      0x0a, 1,  8 , // 2 way set assoc, 32 byte line size
      0x0c, 1, 16 , // 4-way set assoc, 32 byte line size
      0x0d, 1, 16 , // 4-way set assoc, 64 byte line size +
      0x10, 1, 16 , // 4-way set assoc, 64 byte line size
      0x15, 0, 16 , // 4-way set assoc, 64 byte line size
      0x2c, 1, 32 , // 8-way set assoc, 64 byte line size
      0x30, 0, 32 , // 8-way set assoc, 64 byte line size
      0x60, 1, 16 , // 8-way set assoc, sectored cache, 64 byte line size
      0x66, 1,  8 , // 4-way set assoc, sectored cache, 64 byte line size
      0x67, 1, 16 , // 4-way set assoc, sectored cache, 64 byte line size
      0x68, 1, 32 , // 4-way set assoc, sectored cache, 64 byte line size
      0x70, 2, 12 , // 8-way set assoc
      0x71, 2, 16 , // 8-way set assoc
      0x72, 2, 32 , // 8-way set assoc
      0x73, 2, 64 , // 8-way set assoc
      0x77, 0, 16 , // 4-way set assoc, sectored cache, 64 byte line size
      0x00, 0,  0   // sentinel
      };
   int i,j,k,n,sizes[] = {0,0,0};

   cpuid(2,p,"configure_intel");
   n = p[0]&0xff;
   for(i=0;i<n;i++) {
      for(j=0;j<4;j++)
         if (p[j] & 0x80000000) p[j] = 0;
      for(j=0;j<sizeof(regs);j++) {
         if (!regs[j]) continue;
         for(k=0;desc[k]!=0;k+=3)
            if (desc[k]==regs[j]) {
               sizes[desc[k+1]] += desc[k+2];
               break;
               }
         if (DEBUG_ENABLED(DEBUG_CPUID))
            DEBUG_OUT("lookup %x %d %d\n", regs[j], desc[k+1], desc[k+2]);
         }
      if ((i+1)!=n)
         cpuid(2,p,"configure_intel(2)");
      }
   if (sizes[0]<sizes[2])	                  // pentium4 hack
      sizes[0] = sizes[2];
   if ((sizes[0]==0||sizes[1]==0) && lsfn>3) {
      int level, type, ways, parts, lines;
      for(i=0;i<15;i++) {
         p[3] = i;
         cpuid(4,p,"configure_intel(3)");
         if ((type=p[0]&0x1f)==0) break;     // No more info
         level = (p[0]>>5)&7;
         lines = p[1] & 0xfff;
         parts = (p[1]>>12) & 0x3ff;
         ways  = (p[1]>>22) & 0x3ff;
         n     = ((ways+1)*(parts+1)*(lines+1)*(p[2]+1))/1024;
         if (DEBUG_ENABLED(DEBUG_CPUID))
            DEBUG_OUT("type=%d,level=%d,ways=%d,parts=%d,lines=%d,sets=%d: %d\n",
               type,level,ways+1,parts+1,lines+1,p[3]+1,n);
         if (level==1)
            switch(type) {
               case 1:  sizes[1] = n;  break;      // data
               case 2:  sizes[0] = n;  break;      // instruction
               case 3:  sizes[2] = n;  break;      // unified
               }
         }
      }
   if (info.i_cache<1)
      info.i_cache   = sizes[0];
   if (info.d_cache<1)
      info.d_cache   = sizes[1];
   if (info.i_cache>0 && info.d_cache>0)
      return 1;
   return 0;
}

/**
 * Configure the collector for x86 architectures. If a cpuid instruction is present
 * use it to determine the sizes of the data and instruction caches. If these cannot
 * be used supply "generic" defaults.
 */
static int cache_configure(void)
{
  unsigned char regs[4*sizeof(int)];
  unsigned int *p = (unsigned int *)regs;

  if (info.i_cache>0 && info.d_cache>0)
    return 1;
  if (HASCPUID(p)) {
    cpuid(0,p,"max info type");
    switch(p[1]) {
      case 0x68747541:  info.vendor = "amd";       break;
      case 0x69727943:  info.vendor = "cyrix";     break;
      case 0x746e6543:  info.vendor = "centaur";   break;   // aka via
      case 0x756e6547:  info.vendor = "intel";     break;
      case 0x646f6547:  info.vendor = "natsemi";   break;
      case 0x52697365:
      case 0x65736952:  info.vendor = "rise";      break;   // now owned by sis
      case 0x20536953:  info.vendor = "sis";       break;
      default:          info.vendor = "other";     break;
    }
  }
  else p[0]  = 0;
  if (!strcmp(info.vendor,"amd") && configure_amd())
    ;
  else if ( !strcmp(info.vendor,"intel") && configure_intel(p[0]) )
    ;
  else {
    info.generic = 1;
    if (info.d_cache<1)  info.d_cache = HAVEGE_GENERIC_DCACHE;
    if (info.i_cache<1)  info.i_cache = HAVEGE_GENERIC_ICACHE;
  }
  return 1;
}

#else
 /*
 * Configure the collector for other architectures. If command line defaults are not
 * supplied provide "generic" defaults.
 */
static int cache_configure(void)
{
   if (info.i_cache>0 && info.d_cache>0)
      ;
   else {
      info.generic = 1;
      if (info.d_cache<1)  info.d_cache = HAVEGE_GENERIC_DCACHE;
      if (info.i_cache<1)  info.i_cache = HAVEGE_GENERIC_ICACHE;
      }
   return 1;
}
#endif
/*}}}*/

/**
 * The LOOP macro is designed to both size and control the collection loop through use
 * of the loop index. Calculation nodes are numbered from HAVEGE_LOOP_CT down to 0 and
 * for those nodes numbered greater than the loop index, the collection iteration following
 * is executed at the cost of introducing an extra conditional branch.
 *
 * For those nodes numbered less than the loop index, havege_sp() is called to determine
 * the action. If the loop index has not been initialized, the collection iteration is
 * skipped and execution continues at the next loop index. If the loop index has been
 * initialized, control transfers to either the start or end of the collection routine
 * depending upon whether the collection buffer has been filled.
 */
#define LOOP(n,m) loop##n: if (n < loop_idx) { \
                              switch(havege_sp(i,n,LOOP_PT(n))) { \
                                 case 0:   goto loop##m; \
                                 case 1:   goto loop40; \
                                 default:  goto loop_exit; \
                                 } \
                              }
#if 0
#define ROR32(value,shift)   ((value >> (shift)) ^ (value << (32-shift)))
#else
inline DATA_TYPE ror32(const DATA_TYPE value, const DATA_TYPE shift) {
   return (value >> shift) ^ (value << (32 - shift));
}
#define ROR32(value,shift) ror32(value, shift)
#endif

/**
 * Significant variables used in the calculation. The data is declared local to this
 * compile unit but referenced by havege_df() to ensure that a clever optimizer does
 * not decide to ignore the volatile because a variable only has local access.
 */
static volatile DATA_TYPE  havege_bigarray [HAVEGE_NDSIZECOLLECT + 16384];
static volatile DATA_TYPE  ANDPT;
static volatile DATA_TYPE  havege_hardtick;
static volatile DATA_TYPE  loop_idx = HAVEGE_LOOP_CT+1;
static volatile DATA_TYPE  *havege_pwalk;
static volatile char *havege_pts[HAVEGE_LOOP_CT+1];
static volatile DATA_TYPE  *Pt0;
static volatile DATA_TYPE  *Pt1;
static volatile DATA_TYPE  *Pt2;
static volatile DATA_TYPE  *Pt3;
static volatile DATA_TYPE   PT;
static volatile DATA_TYPE   PT2;
static volatile DATA_TYPE   pt2;
static volatile DATA_TYPE   PTtest;

/**
 * Debug setup code
 */
void  havege_debug(H_PTR hptr, char **havege_pts, DATA_TYPE *pts)
{
   int i;

   if (DEBUG_ENABLED(DEBUG_COMPILE))
      for (i=0;i<=(HAVEGE_LOOP_CT+1);i++)
         printf("Address %d=%p\n", i, havege_pts[i]);
   if (DEBUG_ENABLED(DEBUG_LOOP))
      for(i=1;i<(HAVEGE_LOOP_CT+1);i++)
         DEBUG_OUT("Loop %d: offset=%d, delta=%d\n", i,pts[i],pts[i]-pts[i-1]);
}

/**
 * Create a sequence point that is executed for points NOT in the collection
 * sequence. This happens for all points on the collection pass and only for
 * the terminating point thereafter.
 */
static DATA_TYPE havege_sp(DATA_TYPE i, DATA_TYPE n,char *p)
{
  //if (i>0) fprintf(stderr,"collect, i= %d, value RESULT[%d]=%d\n",i,i-1,havege_bigarray[i-1]);
  if (loop_idx < HAVEGE_LOOP_CT)
    return i < HAVEGE_NDSIZECOLLECT? 1 : 2;
  havege_pts[n] = CODE_PT(p);
  if (n==0) loop_idx = 0;
  return 0;
}

/**
 * Initialization routine called from havege_collect() to size the collection loop
 * based on the instruction cache and allocate the walk array based on the size
 * of the data cache.
 */
static volatile DATA_TYPE *havege_tune(H_PTR hptr)
{
  DATA_TYPE offsets[HAVEGE_LOOP_CT+1];
  DATA_TYPE i,offs,*p,sz;

  hptr->havege_buf = (DATA_TYPE *)havege_bigarray;
  for (i=0;i<=HAVEGE_LOOP_CT;i++)
    offsets[i] = abs(havege_pts[i]-havege_pts[HAVEGE_LOOP_CT]);
  havege_debug(hptr, (char **)havege_pts, offsets);
  hptr->loop_idxmax = HAVEGE_LOOP_CT;
  hptr->loop_szmax  = offsets[1];
  if (hptr->i_cache<1 || hptr->d_cache<1)
    return 0;
  sz = hptr->i_cache * 1024;
  for(i=HAVEGE_LOOP_CT;i>0;i--)
    if (offsets[i]>sz)
      break;
  hptr->loop_idx = loop_idx = ++i;
  hptr->loop_sz  = offsets[i];
  ANDPT = ((2*hptr->d_cache*1024)/sizeof(int))-1;
  //p    = (DATA_TYPE *) malloc((ANDPT + 4097)*sizeof(int));
  p    = (DATA_TYPE *) calloc((ANDPT + 4097),sizeof(int));
  offs = (DATA_TYPE)((((LONG_DATA_TYPE)&p[4096])&0xfff)/sizeof(int));
  return &p[4096-offs];
}

/**
 * The collection loop is constructed by repetitions of oneinteration.h with the
 * number of repetitions tailored to the size of the instruction cache. The use
 * of volatile variables forces the compiler to produce the correct sequence of
 * operations for an iteration but DOES NOT prevent compiler optimization of a
 * sequence of interations.
 */
DATA_TYPE havege_collect(volatile H_PTR hptr)
{
   volatile DATA_TYPE * RESULT = havege_bigarray;
   DATA_TYPE i=0,pt=0,inter=0;

//fprintf(stderr,"collect, i= %d, value RESULT[%d]=%d\n",i,i,RESULT[i]);
LOOP(40,39)
   #include "oneiteration.h"
LOOP(39,38)
   #include "oneiteration.h"
LOOP(38,37)
   #include "oneiteration.h"
LOOP(37,36)
   #include "oneiteration.h"
LOOP(36,35)
   #include "oneiteration.h"
LOOP(35,34)
   #include "oneiteration.h"
LOOP(34,33)
   #include "oneiteration.h"
LOOP(33,32)
   #include "oneiteration.h"
LOOP(32,31)
   #include "oneiteration.h"
LOOP(31,30)
   #include "oneiteration.h"
LOOP(30,29)
   #include "oneiteration.h"
LOOP(29,28)
   #include "oneiteration.h"
LOOP(28,27)
   #include "oneiteration.h"
LOOP(27,26)
   #include "oneiteration.h"
LOOP(26,25)
   #include "oneiteration.h"
LOOP(25,24)
   #include "oneiteration.h"
LOOP(24,23)
   #include "oneiteration.h"
LOOP(23,22)
   #include "oneiteration.h"
LOOP(22,21)
   #include "oneiteration.h"
LOOP(21,20)
   #include "oneiteration.h"
LOOP(20,19)
   #include "oneiteration.h"
LOOP(19,18)
   #include "oneiteration.h"
LOOP(18,17)
   #include "oneiteration.h"
LOOP(17,16)
   #include "oneiteration.h"
LOOP(16,15)
   #include "oneiteration.h"
LOOP(15,14)
   #include "oneiteration.h"
LOOP(14,13)
   #include "oneiteration.h"
LOOP(13,12)
   #include "oneiteration.h"
LOOP(12,11)
   #include "oneiteration.h"
LOOP(11,10)
   #include "oneiteration.h"
LOOP(10,9)
   #include "oneiteration.h"
LOOP(9,8)
   #include "oneiteration.h"
LOOP(8,7)
   #include "oneiteration.h"
LOOP(7,6)
   #include "oneiteration.h"
LOOP(6,5)
   #include "oneiteration.h"
LOOP(5,4)
   #include "oneiteration.h"
LOOP(4,3)
   #include "oneiteration.h"
LOOP(3,2)
   #include "oneiteration.h"
LOOP(2,1)
   #include "oneiteration.h"
LOOP(1,0)
   #include "oneiteration.h"
LOOP(0,0)
   havege_sp(i,0,LOOP_PT(0));
   havege_pwalk = havege_tune(hptr);
loop_exit:
  //fprintf(stderr,"collect, i= %d, value RESULT[%d]=%d\n",i,i,RESULT[i]);
  //if (i > 0 ) {
  //  i--;
  //  fprintf(stderr,"collect, i= %d, value RESULT[%d]=%d\n",i,i,RESULT[i]);
  //}
  //info.havege_max_pointer=i;
   return ANDPT==0? 0 : 1;
}
/**
 * This function provides additional optimizer insurance. It should never be called.
 * But because it CAN export the addresses of the calculation static variables to an
 * outside caller, this must further limit any compiler optimizations.
 */

/**
 * This type is used by havege_df() as an affectation to allow static variables
 * escape the optimizers data flow analysis
 */
typedef void volatile * VVAR;

VVAR *havege_df()
{
  static VVAR escape[16] = {
    havege_bigarray,  // 0
    &ANDPT,           // 1
    &havege_hardtick, // 2
    &havege_pwalk,    // 3
    havege_pts,       // 4
    &Pt0,             // 5
    &Pt1,             // 6
    &Pt2,             // 7
    &Pt3,             // 8
    &PT,              // 9
    &PT2,             // 10
    &pt2,             // 11
    &PTtest,          // 12
    0,                // 13
    0,                // 14
    0,                // 15
  };
  return escape;
}

/**
 * Configure the collector
 *
 * Initialize the entropy collector. An intermediate walk table twice the size
 * of the L1 data cache is allocated to be used in permutting processor time
 * stamp readings. This is meant to exercies processort TLBs.
 */
int havege_init(int icache, int dcache, int flags)
{
   info.arch    = ARCH;
   info.vendor  = "";
   info.generic = 0;
   info.i_cache = icache;
   info.d_cache = dcache;

   info.havege_opts = flags;
   if (cache_configure() && havege_collect(&info)!= 0) {
      const int max = HAVEGE_MININITRAND*HAVEGE_CRYPTOSIZECOLLECT/HAVEGE_NDSIZECOLLECT;
      int i;

      for (i = 0; i < max; i++) {
         MSC_START();
         havege_collect(&info);
         MSC_STOP();
         info.etime = MSC_ELAPSED();
         }
      info.havege_ndpt = 0;
      return 0;
      }
   return 1;
}
/**
 * Limit access to our state variable to those who explicity ask
 */
H_RDR havege_state(void)
{
   return &info;
}
/**
 * Debug dump
 */
void havege_status(char *buf, const int buf_size)
{
   const char *fmt =
      "arch:        %s\n"
      "vendor:      %s\n"
      "generic:     %d\n"
      "i_cache:     %d\n"
      "d_cache:     %d\n"
      "loop_idx:    %d\n"
      "loop_idxmax: %d\n"
      "loop_sz:     %d\n"
      "loop_szmax:  %d\n"
      "etime:       %d\n"
      "havege_ndpt  %d\n";
   snprintf(buf,buf_size, fmt,
      info.arch,
      info.vendor,
      info.generic,
      info.i_cache,
      info.d_cache,
      info.loop_idx,
      info.loop_idxmax,
      info.loop_sz,
      info.loop_szmax,
      info.etime,
      info.havege_ndpt
      );
}
/**
 * Main access point
 */
DATA_TYPE ndrand()
{
   if (info.havege_ndpt >= HAVEGE_NDSIZECOLLECT) {
//     if (info.havege_ndpt >= info.havege_max_pointer) {
      MSC_START();
      havege_collect(&info);
      info.havege_ndpt = 0;
      MSC_STOP();
      info.etime = MSC_ELAPSED();
      }
   return info.havege_buf[info.havege_ndpt++];
}

//It will return pointer to READ ONLY!!! buffer containing random data. The size is returned in size parameter.

const DATA_TYPE* ndrand_remaining_buffer(unsigned int *size) {
   DATA_TYPE position=info.havege_ndpt;
   if (info.havege_ndpt >= HAVEGE_NDSIZECOLLECT) {
//     if (info.havege_ndpt >= info.havege_max_pointer) {
      MSC_START();
      havege_collect(&info);
      info.havege_ndpt = 0;
      MSC_STOP();
      info.etime = MSC_ELAPSED();
      }
   *size = HAVEGE_NDSIZECOLLECT - info.havege_ndpt;
   info.havege_ndpt = HAVEGE_NDSIZECOLLECT;
   return info.havege_buf+position;
}

//It will return pointer to READ ONLY!!! buffer containing random data. Size is guaranteed to be HAVEGE_NDSIZECOLLECT
const DATA_TYPE* ndrand_full_buffer() {
   if (info.havege_ndpt > 0) {
      MSC_START();
      havege_collect(&info);
      info.havege_ndpt = 0;
      MSC_STOP();
      info.etime = MSC_ELAPSED();
      }
   info.havege_ndpt = HAVEGE_NDSIZECOLLECT;
   return info.havege_buf;
}

