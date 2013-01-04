/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

C interface for src/QRBG.h

Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>

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

#ifndef QRBG_RNG_H
#define QRBG_RNG_H

#include <inttypes.h>
struct QRBG;

struct QRBG* newQRBG();
void deleteQRBG(struct QRBG *p);

int defineServerQRBG(struct QRBG *p, const char* qrbgServerAddress, unsigned int qrbgServerPort);
int defineUserQRBG(struct QRBG *p, const char* qrbgUsername, const char* qrbgPassword);
int getIntQRBG(struct QRBG *p, int* r);
int getByteQRBG(struct QRBG *p, uint8_t* value);

size_t getIntsQRBG(struct QRBG *p, int* buffer, size_t count);
size_t getBytesQRBG(struct QRBG *p, uint8_t* buffer, size_t count);

#endif

