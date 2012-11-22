#!/bin/sh
/home/jirka/C/64-bit/2012-Mar-25-HELP2MAN/help2man-1.40.7/help2man --section 8 --output=csprngd.8_auto --no-info --libtool ../utils/csprngd
/home/jirka/C/64-bit/2012-Mar-25-HELP2MAN/help2man-1.40.7/help2man --section 1 --output=csprng-generate.1_auto --no-info --libtool ../utils/csprng-generate
/home/jirka/C/64-bit/2012-Mar-25-HELP2MAN/help2man-1.40.7/help2man --section 1 --output=TestU01_raw_stdin_input_with_log.1_auto --no-info ../test/TestU01_raw_stdin_input_with_log

