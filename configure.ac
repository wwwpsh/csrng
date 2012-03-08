## Process this file with autoconf to produce a configure script.

## Minimum Autoconf version
AC_PREREQ(2.65)

#==================================================================
# Be sure to set CSPRNG_LT_VERSION below at the same time
# you change this:
#==================================================================
AC_INIT([csprng],[1.0], [hladky DOT jiri AT gmail DOT com])


AC_CONFIG_AUX_DIR(./config)
# Note that this directory must *exactly* match what was specified via
# -I in ACLOCAL_AMFLAGS in the top-level Makefile.am.
AC_CONFIG_MACRO_DIR(./config)

AC_CONFIG_HEADERS([config.h])

AC_CANONICAL_HOST
AC_DEFINE_UNQUOTED([CHOST], ["$host"], [Canonical host])
AC_CANONICAL_BUILD
AC_DEFINE_UNQUOTED([CBUILD], ["$build"], [Canonical build])
AC_CANONICAL_TARGET
AC_DEFINE_UNQUOTED([CTARGET], ["$target"], [Canonical target])


# Init automake
AM_INIT_AUTOMAKE([1.10 dist-bzip2 subdir-objects foreign tar-ustar -Wall -Werror])

# We want new Libtool
m4_ifdef([LT_PREREQ], [],
	 [m4_fatal([libtool version 2.2.6 or higher is required], [63])])
LT_PREREQ([2.2.6])


CSPRNG_LT_VERSION="1:0:0"
AC_SUBST(CSPRNG_LT_VERSION)
CSPRNG_LIB_VERSION=1.1.0
AC_SUBST(CSPRNG_LIB_VERSION)


AC_LANG([C])

## Checks for programs.
AC_PROG_CC([gcc])

## We will use libtool to create libraries
AC_PROG_LIBTOOL

## Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

## Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([floor gettimeofday memset pow select sqrt clock_gettime])
AC_CHECK_LIB([ssl], [SSL_library_init], [], [AC_MSG_FAILURE([could not find ssl])])

## Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([stdlib.h])
AC_CHECK_HEADERS([string.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([unistd.h])
AC_CHECK_HEADERS([cpuid.h])
AC_CHECK_HEADERS([x86intrin.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([linux/random.h])
AC_CHECK_HEADERS([math.h])
AC_CHECK_HEADERS([time.h])


# At least for glibc, clock_gettime is in librt.  But don't pull that
# in if it still doesn't give us the function we want.
if test $ac_cv_func_clock_gettime = no; then
  AC_CHECK_LIB(rt, clock_gettime,
    [LIBS="-lrt $LIBS"
     AC_DEFINE(HAVE_CLOCK_GETTIME, 1,
	       [Define to 1 if you have the `clock_gettime' function.])])
fi



## Match host to havegedef macros
case "$host" in
 x86_64-*)
    CSPRNG_CPPFLAGS="-DHAVE_ISA_X86 -DHAVE_64"
 ;;

 i*86*-*)
    CSPRNG_CPPFLAGS="-DHAVE_ISA_X86"
 ;;

 ia64-*)
    CSPRNG_CPPFLAGS="-DHAVE_ISA_IA64"
 ;;

 powerpc-*|ppc-*|powerpc64-*|ppc64-*)
    CSPRNG_CPPFLAGS="-DHAVE_ISA_PPC"
 ;;

 sparclite*-*)
    CSPRNG_CPPFLAGS="-DHAVE_ISA_SPACLITE"
 ;;

 sparc*-*)
    CSPRNG_CPPFLAGS="-DHAVE_ISA_SPARC"
 ;;

 *)
    echo "Unsupported host: $host";
    exit 1
 ;;

esac

AC_SUBST(CSPRNG_CPPFLAGS,$CSPRNG_CPPFLAGS)

# Setup libtool
AM_ENABLE_SHARED
AM_DISABLE_STATIC
LT_LANG([C])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 utils/Makefile
                 include/Makefile])


AC_OUTPUT

