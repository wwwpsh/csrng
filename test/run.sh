#!/bin/sh
OUTPUT=/dev/shm/data
set -e
../utils/csprng-generate          | ./TestU01_raw_stdin_input_with_log -n  > normal.txt
../utils/csprng-generate -a       | ./TestU01_raw_stdin_input_with_log -n  > a.txt
../utils/csprng-generate -d       | ./TestU01_raw_stdin_input_with_log -n  > d.txt
../utils/csprng-generate -a -d    | ./TestU01_raw_stdin_input_with_log -n  > ad.txt
../utils/csprng-generate       -r | ./TestU01_raw_stdin_input_with_log -n  > normal_r.txt
../utils/csprng-generate -a    -r | ./TestU01_raw_stdin_input_with_log -n  > ar.txt
../utils/csprng-generate -d    -r | ./TestU01_raw_stdin_input_with_log -n  > dr.txt
../utils/csprng-generate -a -d -r | ./TestU01_raw_stdin_input_with_log -n  > adr.txt

