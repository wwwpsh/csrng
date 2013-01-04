/* vim: set expandtab cindent fdm=marker ts=2 sw=2: */

/* {{{ Copyright notice

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

/*
NIST SP 800-90 CTR_DRBG (Random Number Generator)
*/

#include <csprng/nist_ctr_drbg.h>

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

/*
 * NIST SP 800-90 March 2007
 * 10.4.2 Derivation Function Using a Block Cipher Algorithm
 * Global Constants
 */
static NIST_Key nist_cipher_df_ctx;
static unsigned char nist_cipher_df_encrypted_iv[NIST_BLOCK_SEEDLEN / NIST_BLOCK_OUTLEN][NIST_BLOCK_OUTLEN_BYTES];

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.3.2 The Process Steps for Instantiation When a Derivation
 *            Function is Used
 * Global Constants
 */
static NIST_Key nist_cipher_zero_ctx;

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.5.2 The Process Steps for Generating Pseudorandom Bits When a
 *            Derivation Function is Used for the DRBG Implementation
 * Global Constants
 */
static const unsigned int nist_ctr_drgb_generate_null_input[NIST_BLOCK_SEEDLEN_INTS] = { 0 };


/*
 * Utility
 */
/*
 * nist_increment_block
 *    Increment the output block as a big-endian number.
 */
static void
nist_increment_block(unsigned int* V)
{
  //Increment the output block as a big-endian number
  //unsigned int C[NIST_BLOCK_OUTLEN_INTS];
  //unsigned int O[NIST_BLOCK_OUTLEN_INTS];
  //memcpy(C,V,NIST_BLOCK_OUTLEN_BYTES);
  //memcpy(O,V,NIST_BLOCK_OUTLEN_BYTES);
  //nist_increment_block_orig(C);
	int i;
	unsigned char x;
  unsigned char *p = (unsigned char *)V + ( NIST_BLOCK_OUTLEN_BYTES - 1 );


	for (i = 0; i < NIST_BLOCK_OUTLEN_BYTES; ++i) {
    //dump_hex_byte_string (p, 1, "Old:\t");
    //dump_hex_byte_string ((unsigned char *)V, NIST_BLOCK_OUTLEN_BYTES, "Debug:\t");
		x = *p;
		x++;
    *p = x;
    //dump_hex_byte_string (p, 1, "New:\t");
    //dump_hex_byte_string ((unsigned char *)V, NIST_BLOCK_OUTLEN_BYTES, "Debug:\t");
		if (x)	/* There was only a carry if we are zero */
			//break;
      return;
    p--;
	}
  //if ( memcmp(C,V,NIST_BLOCK_OUTLEN_BYTES) ) {
  //  fprintf(stderr,"Difference\n");
  //  dump_hex_byte_string ((unsigned char *)C, NIST_BLOCK_OUTLEN_BYTES, "Old:\t"); 
  //  dump_hex_byte_string ((unsigned char *)V, NIST_BLOCK_OUTLEN_BYTES, "New:\t"); 
  //  dump_hex_byte_string ((unsigned char *)O, NIST_BLOCK_OUTLEN_BYTES, "Ori:\t"); 
  //
  //}
  //return;
}

void
dump_hex_byte_string (const unsigned char* data, const unsigned int size, const char* message) {
  unsigned int i;
  if (message)
	  fprintf(stderr,"%s",message);

  for (i=0; i<size; ++i) {
	fprintf(stderr,"%02x",data[i]);
  }
  fprintf(stderr,"\n");
}

/*
 * NIST SP 800-90 March 2007
 * 10.4.3 BCC Function
 */
static void
nist_ctr_drbg_bcc_update(const NIST_Key* ctx, const unsigned int* data, unsigned int n, unsigned int *chaining_value)
{
	unsigned int i, j;
	unsigned int input_block[NIST_BLOCK_OUTLEN_INTS];

	/* [4] for i = 1 to n */
	for (i = 0; i < n; ++i) {

		/* [4.1] input_block = chaining_value XOR block_i */
		for (j = 0; j < NIST_BLOCK_OUTLEN_INTS; ++j)
			input_block[j] = chaining_value[j] ^ *data++;

		/* [4.2] chaining_value = Block_Encrypt(Key, input_block) */
		Block_Encrypt(ctx, &input_block[0], &chaining_value[0]);
	}

	/* [5] output_block = chaining_value */
	/* chaining_value already is output_block, so no copy is required */
}

static void
nist_ctr_drbg_bcc(NIST_Key* ctx, const unsigned int* data, int n, unsigned int *output_block)
{
	unsigned int* chaining_value = output_block;

	/* [1] chaining_value = 0^outlen */
	memset(&chaining_value[0], 0, NIST_BLOCK_OUTLEN_BYTES);

	nist_ctr_drbg_bcc_update(ctx, data, n, output_block);
}

/*
 * NIST SP 800-90 March 2007
 * 10.4.2 Derivation Function Using a Block Cipher Algorithm
 */

typedef struct {
	int index;
	unsigned char S[NIST_BLOCK_OUTLEN_BYTES];
} NIST_CTR_DRBG_DF_BCC_CTX;

static __inline int
check_int_alignment(const void* p)
{
	/*
	 * It would be great if "intptr_t" could be found in
	 * some standard place.
	 */
	ptrdiff_t ip = (const char *)p - (const char *)0;

	if (ip & (sizeof(int) - 1))
		return 0;
	
	return 1;
}

static void
nist_ctr_drbg_df_bcc_init(NIST_CTR_DRBG_DF_BCC_CTX* ctx, int L, int N)
{
	unsigned int* S = (unsigned int *)ctx->S;

	/* [4] S = L || N || input_string || 0x80 */
	S[0] = NIST_HTONL(L);
	S[1] = NIST_HTONL(N);
	ctx->index = 2 * sizeof(S[0]);
}

static void
nist_ctr_drbg_df_bcc_update(NIST_CTR_DRBG_DF_BCC_CTX* ctx, const char* input_string, int input_string_length, unsigned int* temp)
{
	int i, len;
	int index = ctx->index;
	unsigned char* S = ctx->S;

	if (index) {
		assert(index < NIST_BLOCK_OUTLEN_BYTES);
		len = NIST_BLOCK_OUTLEN_BYTES - index;
		if (input_string_length < len)
			len = input_string_length;
		
		memcpy(&S[index], input_string, len);

		index += len;
		input_string += len;
		input_string_length -= len;

		if (index < NIST_BLOCK_OUTLEN_BYTES) {
			ctx->index = index;

			return;
		}

		/* We have a full block in S, so let's process it */
		/* [9.2] BCC */
		nist_ctr_drbg_bcc_update(&nist_cipher_df_ctx, (unsigned int *)&S[0], 1, temp);
		index = 0;
	}

	/* ctx->S is empty, so let's handle as many input blocks as we can */
	len = input_string_length / NIST_BLOCK_OUTLEN_BYTES;
	if (len > 0) {
		if (check_int_alignment(input_string)) {
			/* [9.2] BCC */
			nist_ctr_drbg_bcc_update(&nist_cipher_df_ctx, (const unsigned int *)input_string, len, temp);

			input_string += len * NIST_BLOCK_OUTLEN_BYTES;
			input_string_length -= len * NIST_BLOCK_OUTLEN_BYTES;
		} else {
			for (i = 0; i < len; ++i) {
				memcpy(&S[0], input_string, NIST_BLOCK_OUTLEN_BYTES);

				/* [9.2] BCC */
				nist_ctr_drbg_bcc_update(&nist_cipher_df_ctx, (unsigned int *)&S[0], 1, temp);

				input_string += NIST_BLOCK_OUTLEN_BYTES;
				input_string_length -= NIST_BLOCK_OUTLEN_BYTES;
			}
		}
	}

	assert(input_string_length < NIST_BLOCK_OUTLEN_BYTES);

	if (input_string_length) {
		memcpy(&S[0], input_string, input_string_length);
		index = input_string_length;
	}

	ctx->index = index;
}

static void
nist_ctr_drbg_df_bcc_final(NIST_CTR_DRBG_DF_BCC_CTX* ctx, unsigned int* temp)
{
	int index;
	unsigned char* S = ctx->S;
	static const char endmark[] = { 0x80 };

	nist_ctr_drbg_df_bcc_update(ctx, endmark, sizeof(endmark), temp);

	index = ctx->index;
	if (index) {
		memset(&S[index], 0, NIST_BLOCK_OUTLEN_BYTES - index);

		/* [9.2] BCC */
		nist_ctr_drbg_bcc_update(&nist_cipher_df_ctx, (unsigned int *)&S[0], 1, temp);
	}
}

static int
nist_ctr_drbg_block_cipher_df(const char* input_string[], unsigned int L[],
    int input_string_count, unsigned char* output_string, unsigned int N)
{
	int j, k, blocks, sum_L;
	unsigned int *temp;
	unsigned int *X;
	NIST_Key ctx;
	NIST_CTR_DRBG_DF_BCC_CTX df_bcc_ctx;
	unsigned int buffer[NIST_BLOCK_SEEDLEN_INTS];
	/*
	 * NIST SP 800-90 March 2007 10.4.2 states that 512 bits is
	 * the maximum length for the approved block cipher algorithms.
	 */
	unsigned int output_buffer[512 / 8 / sizeof(unsigned int)];

	if (N > sizeof(output_buffer) || N < 1)
		return 0;

	sum_L = 0;
	for (j = 0; j < input_string_count; ++j)
		sum_L += L[j];

	/* [6] temp = Null string */
	temp = buffer;

	/* [9] while len(temp) < keylen + outlen, do */
	for (j = 0; j < NIST_BLOCK_SEEDLEN / NIST_BLOCK_OUTLEN; ++j) {
		/* [9.2] temp = temp || BCC(K, (IV || S)) */

		/* Since we have precomputed BCC(K, IV), we start with that... */ 
		memcpy(&temp[0], &nist_cipher_df_encrypted_iv[j][0], NIST_BLOCK_OUTLEN_BYTES);

		nist_ctr_drbg_df_bcc_init(&df_bcc_ctx, sum_L, N);

		/* Compute the rest of BCC(K, (IV || S)) */
		for (k = 0; k < input_string_count; ++k)
			nist_ctr_drbg_df_bcc_update(&df_bcc_ctx, input_string[k], L[k], temp);

		nist_ctr_drbg_df_bcc_final(&df_bcc_ctx, temp);

		temp += NIST_BLOCK_OUTLEN_INTS;
	}

	nist_zeroize(&df_bcc_ctx, sizeof(df_bcc_ctx));

	/* [6] temp = Null string */
	temp = buffer;

	/* [10] K = Leftmost keylen bits of temp */
	Block_Schedule_Encryption(&ctx, &temp[0]);

	/* [11] X = next outlen bits of temp */
	X = &temp[NIST_BLOCK_KEYLEN_INTS];

	/* [12] temp = Null string */
	temp = output_buffer;

	/* [13] While len(temp) < number_of_bits_to_return, do */
	blocks = (int)(N / NIST_BLOCK_OUTLEN_BYTES);
	if (N & (NIST_BLOCK_OUTLEN_BYTES - 1))
		++blocks;
	for (j = 0; j < blocks; ++j) {
		/* [13.1] X = Block_Encrypt(K, X) */
		Block_Encrypt(&ctx, X, temp);
		X = temp;
		temp += NIST_BLOCK_OUTLEN_INTS;
	}

	/* [14] requested_bits = Leftmost number_of_bits_to_return of temp */
	memcpy(output_string, output_buffer, N);

	nist_zeroize(&ctx, sizeof(ctx));

	return 0;
}


static int
nist_ctr_drbg_block_cipher_df_initialize()
{
	int err;
  unsigned int i;
	unsigned char K[NIST_BLOCK_KEYLEN_BYTES];
	unsigned int IV[NIST_BLOCK_OUTLEN_INTS];

	/* [8] K = Leftmost keylen bits of 0x00010203 ... 1D1E1F */
	for (i = 0; i < sizeof(K); ++i)
		K[i] = (unsigned char)i;

	err = Block_Schedule_Encryption(&nist_cipher_df_ctx, K);
	if (err)
		return err;

	/*
	 * Precompute the partial BCC result from encrypting the IVs:
	 *     nist_cipher_df_encrypted_iv[i] = BCC(K, IV(i))
	 */

	/* [7] i = 0 */
	/* [9.1] IV = i || 0^(outlen - len(i)) */
	memset(&IV[0], 0, sizeof(IV));

		/* [9.3] i = i + 1 */
	for (i = 0; i < NIST_BLOCK_SEEDLEN / NIST_BLOCK_OUTLEN; ++i) {

		/* [9.1] IV = i || 0^(outlen - len(i)) */
		IV[0] = NIST_HTONL(i);

		/* [9.2] temp = temp || BCC(K, (IV || S))  (the IV part, at least) */
		nist_ctr_drbg_bcc(&nist_cipher_df_ctx, &IV[0], 1, (unsigned int *)&nist_cipher_df_encrypted_iv[i][0]); 
	}

	return 0;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.2 The Update Function
 */
static void
nist_ctr_drbg_update(NIST_CTR_DRBG* drbg, const unsigned int* provided_data)
{
unsigned int i;
	unsigned int temp[NIST_BLOCK_SEEDLEN_INTS];
	unsigned int* output_block;

  //dump_hex_byte_string ((unsigned char *)provided_data, NIST_BLOCK_SEEDLEN_BYTES, "Complete provided data:\t\t\t");
	/* 2. while (len(temp) < seedlen) do */
	for (output_block = temp; output_block < &temp[NIST_BLOCK_SEEDLEN_INTS];
		output_block += NIST_BLOCK_OUTLEN_INTS) {

		/* 2.1 V = (V + 1) mod 2^outlen */
		nist_increment_block(&drbg->V[0]);

  //dump_hex_byte_string ((unsigned char *)drbg->V, NIST_BLOCK_KEYLEN_BYTES, "Plaintext:\t"); 
  //dump_hex_byte_string ((unsigned char *)drbg->ctx.key.rd_key, NIST_BLOCK_KEYLEN_BYTES, "Key:\t\t\t");

		/* 2.2 output_block = Block_Encrypt(K, V) */
		Block_Encrypt(&drbg->ctx, drbg->V, output_block);

  //dump_hex_byte_string ((unsigned char *)output_block, NIST_BLOCK_KEYLEN_BYTES, "AES:\t\t\t");

	}

	/* 3 temp is already of size seedlen (NIST_BLOCK_SEEDLEN_INTS) */

  //dump_hex_byte_string ((unsigned char *)provided_data, NIST_BLOCK_KEYLEN_BYTES, "First part provided data:\t\t\t");
	/* 4 (part 1) temp = temp XOR provided_data */
	for (i = 0; i < NIST_BLOCK_KEYLEN_INTS; ++i)
		temp[i] ^= *provided_data++;

	/* 5 Key = leftmost keylen bits of temp */
	Block_Schedule_Encryption(&drbg->ctx, &temp[0]);

	/* 4 (part 2) combined with 6 V = rightmost outlen bits of temp */
  //dump_hex_byte_string ((unsigned char *)provided_data, NIST_BLOCK_KEYLEN_BYTES, "Second part provided data:\t\t\t");
	for (i = 0; i < NIST_BLOCK_OUTLEN_INTS; ++i)
		drbg->V[i] = temp[NIST_BLOCK_KEYLEN_INTS + i] ^ *provided_data++;
}

static int
nist_ctr_drbg_instantiate_initialize()
{
	int err;
	unsigned char K[NIST_BLOCK_KEYLEN_BYTES];

	memset(&K[0], 0, sizeof(K));

	err = Block_Schedule_Encryption(&nist_cipher_zero_ctx, &K[0]);

	return err;
}


/*
 * NIST SP 800-90 March 2007
 * 10.2.1.3.2 The Process Steps for Instantiation When a Derivation
 *            Function is Used
 */
NIST_CTR_DRBG* nist_ctr_drbg_instantiate(
	const void* entropy_input, int entropy_input_length,
	const void* nonce, int nonce_length,
	const void* personalization_string, int personalization_string_length,
        int derive_function)
{
  int err, count;
	unsigned int i;
	unsigned int seed_material[NIST_BLOCK_SEEDLEN_INTS];
	unsigned int personalization_string_processed [NIST_BLOCK_SEEDLEN_INTS];
	unsigned int length[3] = { 0 };
	const char *input_string[3];
  NIST_CTR_DRBG* drbg;

  drbg = calloc(1, sizeof(NIST_CTR_DRBG));
  if ( drbg == NULL ) {
    fprintf ( stderr, "nist_ctr_drbg_instantiate: Dynamic memory allocation failed\n" );
    return drbg;
  }

	drbg->derive_function = derive_function;

	if ( drbg->derive_function ) {
		/* [1] seed_material = entropy_input || nonce || personalization_string */
		//fprintf(stderr,"Using derive function");
		input_string[0] = entropy_input;
		length[0] = entropy_input_length;

		input_string[1] = nonce;
		length[1] = nonce_length;

		count = 2;
		if (personalization_string) {
			input_string[count] = personalization_string;
			length[count] = personalization_string_length;
			++count;
		}
                //10.2.1.3.2  The Process Steps for Instantiation When a Derivation Function is Used 
                //1.  seed_material  = entropy_input  ||  nonce ||  personalization_string. 
                //Comment: Ensure that the length of the seed_material  is exactly  seedlen bits

                //fprintf(stderr, "length[0]: %u, length[1]: %u, length[2]: %u, SEEDLEN_INTS: %u\n", length[0], length[1], length[2], NIST_BLOCK_SEEDLEN_BYTES);
                assert( length[0] +  length[1] + length[2] == NIST_BLOCK_SEEDLEN_BYTES );
		/* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
		err = nist_ctr_drbg_block_cipher_df(input_string, length, count,
				(unsigned char *)seed_material, sizeof(seed_material));
		if (err)
			return NULL;
	} else {
		//fprintf(stderr,"No derive function");

/*
 * 10.2.1.3.1 Instantiation When Full Entropy is Available for the Entropy
 *            Input, and a Derivation Function is Not Used
 */
		/* [1]  temp = len (personalization_string) */
/* [2] If (temp < seedlen), then personalization_string = personalization_string ||0^(seedlen - temp)
 * [3] seed_material = entropy_input XOR personalization_string */
		if (personalization_string_length > NIST_BLOCK_SEEDLEN_BYTES)
			return NULL;
		if ( entropy_input_length != NIST_BLOCK_SEEDLEN_BYTES)
			return NULL;

		memcpy(seed_material, entropy_input, NIST_BLOCK_SEEDLEN_BYTES);

                if (personalization_string) {
			if (personalization_string_length < NIST_BLOCK_SEEDLEN_BYTES) {
				memcpy(personalization_string_processed, personalization_string, personalization_string_length);
				memset(personalization_string_processed+personalization_string_length,0,NIST_BLOCK_SEEDLEN_BYTES-personalization_string_length);
			} else {
				memcpy(personalization_string_processed, personalization_string, NIST_BLOCK_SEEDLEN_BYTES);
			}
			
			for (i = 0; i < NIST_BLOCK_KEYLEN_INTS; ++i)
				seed_material[i] ^= personalization_string_processed[i];
		}
	}          


	/* [3] Key = 0^keylen */
	memcpy(&drbg->ctx, &nist_cipher_zero_ctx, sizeof(drbg->ctx));

	/* [4] V = 0^outlen */
	memset(&drbg->V, 0, sizeof(drbg->V));

	/* [5] (Key, V) = Update(seed_material, Key, V) */
	nist_ctr_drbg_update(drbg, seed_material);

	/* [6] reseed_counter = 1 */
	drbg->reseed_counter = 1;

	return drbg;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.4.2 The Process Steps for Reseeding When a Derivation
 *            Function is Used
 */
int
nist_ctr_drbg_reseed(NIST_CTR_DRBG* drbg,
	const void* entropy_input, int entropy_input_length,
	const void* additional_input, int additional_input_length)
{
  unsigned int i;
	int err, count;
	const char *input_string[2];
	unsigned int length[2] = { 0 };
	unsigned int seed_material[NIST_BLOCK_SEEDLEN_INTS];
	unsigned int additional_input_processed[NIST_BLOCK_SEEDLEN_INTS];

#if 0
  static uint64_t calls = 0;
  ++calls;
  fprintf(stderr, "nist_ctr_drbg_reseed %"PRIu64"\n", calls);
#endif  

	if ( drbg->derive_function ) {
		/* [1] seed_material = entropy_input || additional_input */
		input_string[0] = entropy_input;
		length[0] = entropy_input_length;
		count = 1;

		if (additional_input) {
			input_string[count] = additional_input;
			length[count] = additional_input_length;
			
			++count;
		}
                //10.2.1.4.2  The Process Steps for Reseeding When a Derivation Function is Used 
                //seed_material  = entropy_input  ||  additional_input
                //Comment: Ensure that the length of the seed_material  is exactly  seedlen bits.
                //fprintf(stderr, "length[0]: %u, length[1]: %u, SEEDLEN_INTS: %u\n", length[0], length[1], NIST_BLOCK_SEEDLEN_BYTES);
                assert( length[0] + length[1] == NIST_BLOCK_SEEDLEN_BYTES ); 
		/* [2] seed_material = Block_Cipher_df(seed_material, seedlen) */
		err = nist_ctr_drbg_block_cipher_df(input_string, length, count,
				(unsigned char *)seed_material, sizeof(seed_material));
		if (err)
			return err;

	} else {
/* 10.2.1.4.1
Reseeding When Full Entropy is Available for the Entropy
Input, and a Derivation Function is Not Used
*/
/*
1. temp = len (additional_input).
2. If (temp < seedlen), then additional_input = additional_input || 0seedlen - temp.
3. seed_material = entropy_input ⊕ additional_input.
*/
		if ( additional_input_length > NIST_BLOCK_SEEDLEN_BYTES)
			return 1;
		if ( entropy_input_length != NIST_BLOCK_SEEDLEN_BYTES)
			return 1;

		memcpy(seed_material, entropy_input, NIST_BLOCK_SEEDLEN_BYTES);

		if ( additional_input ) {
			if ( additional_input_length < NIST_BLOCK_SEEDLEN_BYTES) {
				memcpy(additional_input_processed, additional_input, additional_input_length);
				memset(additional_input_processed+additional_input_length,0,NIST_BLOCK_SEEDLEN_BYTES-additional_input_length);
			} else {
				memcpy(additional_input_processed, additional_input, NIST_BLOCK_SEEDLEN_BYTES);
			}
			for (i = 0; i < NIST_BLOCK_KEYLEN_INTS; ++i)
				seed_material[i] ^= additional_input_processed[i];
		}
	}

	/* [3] (Key, V) = Update(seed_material, Key, V) */
	nist_ctr_drbg_update(drbg, seed_material);

	/* [4] reseed_counter = 1 */
	drbg->reseed_counter = 1;

	return 0;
}

/*
 * NIST SP 800-90 March 2007
 * 10.2.1.5.2 The Process Steps for Generating Pseudorandom Bits When a
 *            Derivation Function is Used for the DRBG Implementation
 */
static void
nist_ctr_drbg_generate_block(NIST_CTR_DRBG* drbg, unsigned int* output_block)
{
	/* [4.1] V = (V + 1) mod 2^outlen */
	nist_increment_block(&drbg->V[0]);

	/* [4.2] output_block = Block_Encrypt(Key, V) */
	Block_Encrypt(&drbg->ctx, &drbg->V[0], output_block);
}

int
nist_ctr_drbg_generate(NIST_CTR_DRBG* drbg,
	void* output_string, int output_string_length,
	const void* additional_input, int additional_input_length)
{
	int i, len, err;
	int blocks = output_string_length / NIST_BLOCK_OUTLEN_BYTES;
	unsigned char* p;
	unsigned int* temp;
	const char *input_string[1];
	unsigned int length[1] = { 0 };
	unsigned int buffer[NIST_BLOCK_OUTLEN_BYTES];
	unsigned int additional_input_buffer[NIST_BLOCK_SEEDLEN_INTS];

#if 0
  static uint64_t calls = 0;
  ++calls;
  fprintf(stderr, "nist_ctr_drbg_generate %"PRIu64"\n", calls);
#endif

	if (output_string_length < 1) {
    fprintf(stderr, "nist_ctr_drbg_generate: output_string_length %d has to be bigger than 0\n", output_string_length);
    return 1;
  }
  //2^19 is specified as max_number_of_bits_per_request in table 3, section 10.2.1
	if (output_string_length > (int) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST ) {
    fprintf(stderr, "nist_ctr_drbg_generate: maximum output_string_length is %d bytes, requested was %d bytes\n",
        (int) NIST_CTR_DRBG_MAX_NUMBER_OF_BYTES_PER_REQUEST, output_string_length);
		return 1;
  }
 

	/* [1] If reseed_counter > reseed_interval ... */
	if (drbg->reseed_counter >= NIST_CTR_DRBG_RESEED_INTERVAL) {
    fprintf(stderr, "nist_ctr_drbg_generate: reseed required. reseed_counter %" PRIu64 " has reached the limit of %d\n",
        drbg->reseed_counter, (int) NIST_CTR_DRBG_RESEED_INTERVAL );
		return 1;
  }

	if ( drbg->derive_function ) {

		/* [2] If (addional_input != Null), then */
		if (additional_input && additional_input_length>0) {
			input_string[0] = additional_input;
			length[0] = additional_input_length;
                        
                        //10.2.1.5.2  The Process Steps for Generating  Pseudorandom Bits When a Derivation Function
                        // is Used for the DRBG Implementation 
                        // Requirement that the length of the additional_input  is exactly seedlen bits is not specified in the NIST SP800-90
                        // but it's IMHO (Jirka Hladky) very reasonable
                        //fprintf(stderr, "length[0]: %u, SEEDLEN_INTS: %u\n", length[0], NIST_BLOCK_SEEDLEN_BYTES);
                        assert( length[0] == NIST_BLOCK_SEEDLEN_BYTES );
			/* [2.1] additional_input = Block_Cipher_df(additional_input, seedlen) */
			err = nist_ctr_drbg_block_cipher_df(input_string, length, 1,
					(unsigned char *)additional_input_buffer, sizeof(additional_input_buffer));
			if (err) {
        fprintf(stderr, "nist_ctr_drbg_generate: nist_ctr_drbg_block_cipher_df (DERIVATION FUNCTION) has failed.\n");
				return err;
      }

			/* [2.2] (Key, V) = Update(additional_input, Key, V) */
			nist_ctr_drbg_update(drbg, additional_input_buffer);
		}

		if (blocks && check_int_alignment(output_string)) {
			/* [3] temp = Null */
			temp = (unsigned int *)output_string;
			for (i = 0; i < blocks; ++i) {
				nist_ctr_drbg_generate_block(drbg, temp);

				temp += NIST_BLOCK_OUTLEN_INTS;
				output_string_length -= NIST_BLOCK_OUTLEN_BYTES;
			}

			output_string = (unsigned char *)temp;
		}
	} else {
/*
10.2.1.5.1
Generating Pseudorandom Bits When a Derivation Function is
Not Used for the DRBG Implementation
*/
/*
2. If (additional_input ≠ Null), then
	2.1 temp = len (additional_input).
	2.2 If (temp < seedlen), then
	additional_input = additional_input || 0^(seedlen - temp)
	2.3 (Key, V) = CTR_DRBG_Update (additional_input, Key, V).
Else additional_input = 0^seedlen.
*/		
		if ( additional_input && additional_input_length > 0 ) {
			if ( additional_input_length > NIST_BLOCK_SEEDLEN_BYTES)
				return 1;

			if ( additional_input_length < NIST_BLOCK_SEEDLEN_BYTES) {
				memcpy(additional_input_buffer, additional_input, additional_input_length);
				memset(additional_input_buffer+additional_input_length,0,NIST_BLOCK_SEEDLEN_BYTES-additional_input_length);
				
			} else {
				memcpy(additional_input_buffer, additional_input,NIST_BLOCK_SEEDLEN_BYTES);
			}
      nist_ctr_drbg_update(drbg, additional_input_buffer);
		}
		//} else {
		//	memset(additional_input_buffer, 0, NIST_BLOCK_SEEDLEN_BYTES);;
		//}
		//We create string with 0 directly at step [6] when needed
	}

	
	/* [3] temp = Null */
	temp = buffer;

	len = NIST_BLOCK_OUTLEN_BYTES;

	/* [4] While (len(temp) < requested_number_of_bits) do: */
	p = output_string;
	while (output_string_length > 0) {
		nist_ctr_drbg_generate_block(drbg, temp);

		if (output_string_length < NIST_BLOCK_OUTLEN_BYTES)
			len = output_string_length;

		memcpy(p, temp, len);

		p += len;
		output_string_length -= len;
	}

	/* [6] (Key, V) = Update(additional_input, Key, V) */
	nist_ctr_drbg_update(drbg, (additional_input && additional_input_length>0) ?
		&additional_input_buffer[0] :
		&nist_ctr_drgb_generate_null_input[0]);

	/* [7] reseed_counter = reseed_counter + 1 */
	++drbg->reseed_counter;

	return 0;
}

int
nist_ctr_initialize()
{
	int err;

	err = nist_ctr_drbg_instantiate_initialize();
	if (err)
		return err;
	err = nist_ctr_drbg_block_cipher_df_initialize();
	if (err)
		return err;

	return 0;
}

int
nist_ctr_drbg_destroy(NIST_CTR_DRBG* drbg)
{
  if ( drbg != NULL ) {
    nist_zeroize(drbg, sizeof(*drbg));
    drbg->reseed_counter = ~0U;
    free(drbg);
  }

  return 0;
}
