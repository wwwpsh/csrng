/* SP 800-90 random number generator
 *
 * Code by Henric Jungheim <software@henric.info> found at http://henric.info/random/
 * Compacted and adapted for OpenSSL by Yair Elharrar, Jul 2010
 *
 * This code implements the CTR_DRBG algorithm defined in section 10.2, based on AES-128 with DF.
 * Prediction Resistance is not supported.
 *
 */

/*
 * Copyright (c) 2007 Henric Jungheim <software@henric.info>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

// uint64_t
// Otherwise
// typedef unsigned long long uint64_t;
#include <stdint.h>

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
#define NIST_CTR_DRBG_RESEED_INTERVAL	(1ULL<<48)
//#define NIST_CTR_DRBG_RESEED_INTERVAL 512

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

extern int
	nist_ctr_drbg_instantiate(NIST_CTR_DRBG* drbg,
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

