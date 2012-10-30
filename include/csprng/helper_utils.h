/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice
Copyright (C) 2011, 2012 Jirka Hladky

This file is part of CSRNG http://code.google.com/p/csrng/

CSRNG is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CSRNG is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with CSRNG.  If not, see <http://www.gnu.org/licenses/>.
}}} */

#ifndef HELPER_UTILS_H
#define HELPER_UTILS_H

#include <inttypes.h>
#include <time.h>

int64_t elapsed_time(struct timespec *start, struct timespec *stop);
uint64_t int_pow(uint64_t x, uint64_t p);
const char* human_print_int (uint64_t number_of_bytes);
const char* human_print_ldouble (uint64_t number_of_bytes);
const char* human_print_ldouble_left_alligned (uint64_t number_of_bytes);
#endif

