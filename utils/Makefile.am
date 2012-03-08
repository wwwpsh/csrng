bin_PROGRAMS = csprng-generate csprngd

csprng_generate_CPPFLAGS = -I$(top_srcdir)/include
csprng_generate_LDADD = $(top_builddir)/src/libcsprng.la -lm
csprng_generate_SOURCES = csprng-generate.c 

csprngd_CPPFLAGS = -I$(top_srcdir)/include
csprngd_LDADD = $(top_builddir)/src/libcsprng.la -lm
csprngd_SOURCES = random_interface_linux.h random_interface_linux.c csprngd.c

MAINTAINERCLEANFILES = Makefile.in

