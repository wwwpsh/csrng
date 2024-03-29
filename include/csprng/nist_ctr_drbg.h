/* vim:set ts=2 sw=2 sts=2 foldmethod=marker smarttab: */

/* {{{ Copyright notice

Header file of Block Cipher Based CTR_DRBG
DRBG =  deterministic random bit generator
CTR =   Counter (CTR) mode of operation of the block cipher (AES-128 in this case)

SP 800-90 random number generator
This code implements the CTR_DRBG algorithm defined in section 10.2, based on AES-128 with DF.

Copyright (C) 2011-2013 Jirka Hladky <hladky DOT jiri AT gmail DOT com>
Copyright (C) 2010 Yair Elharrar (compacted and adapted for OpenSSL)
Copyright (C) 2007 Henric Jungheim <software@henric.info>

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

#ifndef NIST_CTR_DRBG_H
#define NIST_CTR_DRBG_H

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

// uint64_t
// Otherwise
// typedef unsigned long long uint64_t;
#include <inttypes.h>

//Functions ntohl, htonl : handling endianness
//Alternative: /usr/include/endian.h
#include <arpa/inet.h>


/* Choose AES-128 as the underlying block cipher */
#define NIST_BLOCK_KEYLEN		(128)
#define NIST_BLOCK_KEYLEN_BYTES	(NIST_BLOCK_KEYLEN / 8)
#define NIST_BLOCK_KEYLEN_INTS	(NIST_BLOCK_KEYLEN_BYTES / sizeof(int))

#define NIST_BLOCK_OUTLEN		(128)
#define NIST_BLOCK_OUTLEN_BYTES	(NIST_BLOCK_OUTLEN / 8)
#define NIST_BLOCK_OUTLEN_INTS	(NIST_BLOCK_OUTLEN_BYTES / sizeof(int))

typedef struct { 
	AES_KEY key;
} NIST_Key;


#define NIST_NTOHL ntohl
#define NIST_HTONL htonl

/*
 * NIST SP 800-90 March 2007
 * 10.2 DRBG Mechanism Based on Block Ciphers
 *
 * Table 3 specifies the reseed interval as
 * <= 2^48.
 *
 */

//Maximum bits to get without reseed
#define NIST_CTR_DRBG_RESEED_INTERVAL	(1ULL<<48)

//2^19 is specified as max_number_of_bits_per_request in table 3, section 10.2.1
#define NIST_CTR_DRBG_MAX_NUMBER_OF_BITS_PER_REQUEST (1ULL<<19)
#define NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST (NIST_CTR_DRBG_MAX_NUMBER_OF_BITS_PER_REQUEST / 8)


#define NIST_BLOCK_SEEDLEN			(NIST_BLOCK_KEYLEN + NIST_BLOCK_OUTLEN)
#define NIST_BLOCK_SEEDLEN_BYTES	(NIST_BLOCK_SEEDLEN / 8)
#define NIST_BLOCK_SEEDLEN_INTS		(NIST_BLOCK_SEEDLEN_BYTES / sizeof(int))

#define Block_Encrypt(ctx, src, dst) AES_encrypt((unsigned char *)(src), (unsigned char *)(dst), &(ctx)->key)
#define Block_Schedule_Encryption(xx, yy) AES_set_encrypt_key((unsigned char *)(yy), NIST_BLOCK_KEYLEN, &(xx)->key)
#define nist_zeroize(buf, len) memset((buf), 0, (len))

typedef struct {
	uint64_t reseed_counter;
	NIST_Key ctx;
	unsigned int V[NIST_BLOCK_OUTLEN_INTS];
        //Infrastructure
        //derive function (0=false, 1=true)
	int derive_function;
        //prediction resistance (0=false, 1=true)
        //int prediction_resistance;
} NIST_CTR_DRBG;

/* Function interface */

extern NIST_CTR_DRBG*
	nist_ctr_drbg_instantiate(
                const void* entropy_input, int entropy_input_length,
		const void* nonce, int nonce_length,
		const void* personalization_string, int personalization_string_length,
                int derive_function);
extern int
	nist_ctr_drbg_reseed(NIST_CTR_DRBG* drbg,
		const void* entropy_input, int entropy_input_length,
		const void* additional_input, int additional_input_length);
extern int
	nist_ctr_drbg_generate(NIST_CTR_DRBG* drbg,
		void* output_string, int output_string_length,
		const void* additional_input, int additional_input_length);
extern int
	nist_ctr_initialize();
extern int
	nist_ctr_drbg_destroy(NIST_CTR_DRBG* drbg);

extern void
dump_hex_byte_string (const unsigned char* data, const unsigned int size, const char* message);

#endif
