include $(top_srcdir)/common.mk

bin_PROGRAMS = csprng-generate
sbin_PROGRAMS = csprngd

csprng_generate_CPPFLAGS = -I$(top_srcdir)/include
csprng_generate_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt
csprng_generate_SOURCES = csprng-generate.c 

csprngd_CPPFLAGS = -I$(top_srcdir)/include
csprngd_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt
csprngd_SOURCES = random_interface_linux.h random_interface_linux.c csprngd.c

MAINTAINERCLEANFILES = Makefile.in

