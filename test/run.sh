#!/bin/sh
set -e
../utils/csprng-generate          | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > normal.txt
../utils/csprng-generate -a       | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > a.txt
../utils/csprng-generate -d       | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > d.txt
../utils/csprng-generate -a -d    | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > ad.txt
../utils/csprng-generate       -r | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > normal_r.txt
../utils/csprng-generate -a    -r | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > ar.txt
../utils/csprng-generate -d    -r | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > dr.txt
../utils/csprng-generate -a -d -r | ./TestU01_raw_stdin_input_with_log -n -o /dev/shm/A/data/rand > adr.txt

