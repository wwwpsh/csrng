bin_PROGRAMS = csprng csprng-generate

csprng_CPPFLAGS = -I$(top_srcdir)/include
csprng_LDADD = $(top_builddir)/src/libcsprng.la
csprng_SOURCES = main.c


csprng_generate_CPPFLAGS = -I$(top_srcdir)/include
csprng_generate_LDADD = $(top_builddir)/src/libcsprng.la -lm
csprng_generate_SOURCES = csprng-generate.c

MAINTAINERCLEANFILES = Makefile.in

