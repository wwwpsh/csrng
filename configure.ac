## Process this file with autoconf to produce a configure script.

## Minimum Autoconf version
AC_PREREQ(2.65)

#==================================================================
# Be sure to set CSPRNG_LT_VERSION below at the same time
# you change this:
#==================================================================
AC_INIT([csprng],[1.1.3], [hladky DOT jiri AT gmail DOT com])

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
AM_INIT_AUTOMAKE([1.10 dist-bzip2 subdir-objects foreign tar-ustar -Wall -Werror ])

LT_INIT

CSPRNG_LT_VERSION="1:0:0"
AC_SUBST(CSPRNG_LT_VERSION)
CSPRNG_LIB_VERSION=1.1.0
AC_SUBST(CSPRNG_LIB_VERSION)


AC_LANG([C],[C++])

## Checks for programs.
AC_PROG_CC([gcc])
AC_PROG_CXX([g++])

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

#### Find OpenSSL
AC_CHECK_LIB([crypto],[CRYPTO_new_ex_data], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_LIB([ssl],[SSL_library_init], [], [AC_MSG_ERROR([OpenSSL libraries required])])
AC_CHECK_HEADERS([openssl/err.h openssl/rand.h openssl/sha.h openssl/bn.h],[],[AC_MSG_ERROR([OpenSSL headers required])])

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
AC_CHECK_HEADERS([openssl/sha.h])


AC_CHECK_LIB(rt, clock_gettime,
             [LIBS="-lrt $LIBS"
              AC_DEFINE(HAVE_CLOCK_GETTIME, 1,
                        [Define to 1 if you have the `clock_gettime' function.])])

## AC_ARG_WITH(option-name, help-string, action-if-present, action-if-not-present)

AC_ARG_WITH(
	[testu01],
	[AS_HELP_STRING([--with-testu01],[Enable statistical testing of uniform random number generators using TestU01])])

AS_IF([test "x$with_testu01" = "xyes"], [
  AC_CHECK_LIB([testu01], [bbattery_SmallCrush], [AM_CONDITIONAL([HAVE_LIBTESTU01], true)], [AC_MSG_ERROR([Could  not find TestU01 library])])], [
  AM_CONDITIONAL([HAVE_LIBTESTU01], false) ])

AC_ARG_WITH(
	[havege],
	[AS_HELP_STRING([--without-havege],[Do not use external havege library. Instead, use the internal version of the HAVEGE algorithm])])

AS_IF([test "x$with_havege" = "xno"], [
      ## Disable search for the external havege libraries. Do not link with -lhavege
       AM_CONDITIONAL([LINK_WITH_HAVEGE], false)
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
      ], [
      ## Check for the havege libraries and header files           
      AC_CHECK_LIB([havege],[havege_create], [], [AC_MSG_ERROR([HAVEGED libraries required])])
      AC_CHECK_HEADERS([haveged/havege.h],[],[AC_MSG_ERROR([HAVEGED headers required])])
      AM_CONDITIONAL([LINK_WITH_HAVEGE], true)])


# Setup libtool
AM_ENABLE_SHARED
AM_DISABLE_STATIC
LT_LANG([C])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 utils/Makefile
                 include/Makefile
                 test/Makefile
                 man/Makefile])


AC_OUTPUT

