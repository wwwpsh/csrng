## Process this file with autoconf to produce a configure script.

## Minimum Autoconf version
AC_PREREQ(2.65)

AC_INIT([csprng],[1.0], [hladky DOT jiri AT gmail DOT com])
AC_CONFIG_SRCDIR([/src/csprng.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE

## Checks for programs.
AC_PROG_CC([gcc])

## Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

## Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([floor gettimeofday memset pow select sqrt])
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

AC_CANONICAL_HOST

## Match host to havegedef macros
case "$host" in
 x86_64-*)
    HA_CPPFLAGS="-DHAVE_ISA_X86 -DHAVE_64"
 ;;

 i*86*-*)
    HA_CPPFLAGS="-DHAVE_ISA_X86"
 ;;

 ia64-*)
    HA_CPPFLAGS="-DHAVE_ISA_IA64"
 ;;

 powerpc-*|ppc-*|powerpc64-*|ppc64-*)
    HA_CPPFLAGS="-DHAVE_ISA_PPC"
 ;;

 sparclite*-*)
    HA_CPPFLAGS="-DHAVE_ISA_SPACLITE"
 ;;

 sparc*-*)
    HA_CPPFLAGS="-DHAVE_ISA_SPARC"
 ;;

 *)
    echo "Unsupported host: $host";
    exit 1
 ;;

esac

## Set hardware depedent define for the build
AC_SUBST(HA_CPPFLAGS,$HA_CPPFLAGS)

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
