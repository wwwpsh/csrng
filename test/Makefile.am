include $(top_srcdir)/common.mk

#AM_LDFLAGS = -static
#bin_PROGRAMS = openssl-rand sha1_main memt qrbg_main http_main ctr_drbg_test
#TODO - link static does not work for qrbg_main.c => move it to C++ ??

bin_PROGRAMS = openssl-rand_main sha1_main memt_main qrbg_main http_main ctr_drbg_test havege_main 
if HAVE_LIBTESTU01
  bin_PROGRAMS += TestU01_raw_stdin_input_with_log
endif

openssl_rand_main_SOURCES = openssl-rand_main.c
openssl_rand_main_LDADD = -lcrypto

sha1_main_CPPFLAGS = -I$(top_srcdir)/include
sha1_main_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt -lcrypto
sha1_main_SOURCES = sha1_main.c

memt_main_CPPFLAGS = -I$(top_srcdir)/include
memt_main_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt
memt_main_SOURCES = memt_main.c

qrbg_main_CPPFLAGS = -I$(top_srcdir)/include
qrbg_main_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt
qrbg_main_SOURCES = qrbg_main.c

http_main_CPPFLAGS = -I$(top_srcdir)/include
http_main_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt
http_main_SOURCES = http_main.c

ctr_drbg_test_CPPFLAGS = -I$(top_srcdir)/include
ctr_drbg_test_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt
ctr_drbg_test_SOURCES = ctr_drbg_test.c

havege_main_CPPFLAGS = -I$(top_srcdir)/include
havege_main_LDADD = $(top_builddir)/src/libcsprng.la -lm -lrt -lcrypto
havege_main_SOURCES = havege_main.c

if HAVE_LIBTESTU01
TestU01_raw_stdin_input_with_log_LDADD = -ltestu01
TestU01_raw_stdin_input_with_log_SOURCES = TestU01_raw_stdin_input_with_log.c
endif


MAINTAINERCLEANFILES = Makefile.in

