include $(top_srcdir)/common.mk

VERSION=@VERSION@

# Note that the -I directory must *exactly* match what was specified
# via AC_CONFIG_MACRO_DIR in configure.ac.
ACLOCAL_AMFLAGS = -I ./config

AM_CFLAGS += $(CSPRNG_CPPFLAGS)
AM_CPPFLAGS = $(CSPRNG_CPPFLAGS)
AM_LDFLAGS = $(CSPRNG_LDFLAGS)

lib_LTLIBRARIES = libcsprng.la

libcsprng_la_LIBADD =
libcsprng_la_CPPFLAGS = -I$(top_srcdir)/include
libcsprng_la_LDFLAGS = -version-number @CSPRNG_LT_VERSION@

# Sources
# The shell script is the easy way to do this, by far.  But it may not
# be sufficiently portable.
# libdieharder_la_SOURCES = $(shell ls *.c  2>&1 | sed -e "/\/bin\/ls:/d")
libcsprng_la_SOURCES = \
		       cpuid-43.h \
		       oneiteration.h \
		       helper_utils.c \
                       havege.c \
		       nist_ctr_drbg_mod.c \
		       csprng.c \
		       memt19937ar-JH.c \
		       sha1_rng.c \
                       fips.c \
                       QRBG.h \
                       QRBG.cpp \
                       qrbg-c.cpp \
		       http_rng.c

MAINTAINERCLEANFILES = Makefile.in






