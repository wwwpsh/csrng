/*
gcc -Wall -o  jh_ctr_drbg_main  jh_ctr_drbg_main.c  nist_ctr_drbg_mod.c -lcrypto
./ jh_ctr_drbg_main | pv >/dev/null

gcc -Wall -O2 -o  jh_ctr_drbg_main  jh_ctr_drbg_main.c  nist_ctr_drbg_mod.c -lcrypto

../cbc-mac_1 | pv -Ncbc-mac -c -W | ./jh_ctr_drbg_main  | pv -Nctr_drbg -c -W >/dev/null

../cbc-mac_1 | pv -Ncbc-mac -c -W | ./jh_ctr_drbg_main  | pv -Nctr_drbg -c -W | ~/C/DIEHARDER/dieharder-3.31.0/dieharder/dieharder -a -g 200 | tee dieharder.log
../cbc-mac_1 | ./jh_ctr_drbg_main | ~/C/DIEHARDER/dieharder-3.31.0/dieharder/dieharder -a -g 200 | tee dieharder.log1
./jh_ctr_drbg_main </dev/zero | ~/C/DIEHARDER/dieharder-3.31.0/dieharder/dieharder -a -g 200 | tee dieharder.log2

gcc -Wall -I ../src/ -o ctr_drbg_test ctr_drbg_test.c  ../src/nist_ctr_drbg_mod.c -lcrypto
./ctr_drbg_test -e a12334716c4020e6c463867b6b878ddd | od -t x1

gcc -Wall -g -I ../src/ -o ctr_drbg_test ctr_drbg_test.c  ../src/nist_ctr_drbg_mod.c -lcrypto
valgrind --track-origins=yes ./ctr_drbg_test -e 64dce30c15fece81516d766fedc62279b0ae6b28651b79d240e180cd757e7cd4 -r 0df1949009d7bb72bd786e1a6a79c468981252b84bfc7f79859c23f3ff706553 -n 16e086ad1715b000


./ctr_drbg_test -l 256 -k 64 -e 5268405a8f07907e84048cec89d08a969ffd2aae0505120b1759eeda6eaca688 -r 041ccd9e339e3261d7304621f9e0fe195481babb9393a036cb7535403bcd3c2b
=>23661d7c40f5d5e39530201a5397602e

./ctr_drbg_test -d -l 128 -k 64 -e 7c0fe58f8f62c25eadbe24600b78426a -r 9df9a69cd131028a055e9ec1e483f37c -n d939ad1e08a80244
=> 3487018af191fa961fefac2854d96bf5
*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include "nist_ctr_drbg.h"

//Use derive_function ? 0=false, 1=true
#define DERIVE_FUNCTION 0

int read_data (int fd, void *buf, size_t count) {
  
  int number_of_chars;
  int position = 0;
  
  while (position < count ) {
    number_of_chars  = read(fd,buf+position,count );
    
    if (number_of_chars == 0 ) {
      fprintf(stderr, "Error: end of file. No more input data, closing\n");
      exit(0);
    } else if (number_of_chars<0  ) {
      if ((errno == EAGAIN) || (errno == ENOMEM) || (errno == EINTR) || (errno=EWOULDBLOCK) ){
        continue;
      } else {
	perror("Error during read function call\n");
	exit(1);
      }
    }
    position +=  number_of_chars;
  }
  return position;
}

int main(int argc, char **argv) {
  static const char* cmds[] = {
    "e", "entropy",              "1", "EntropyInput as big-endian char string, 128bits long",
    "r", "entropyReseed",        "1", "EntropyInputReseed, 128bits long",
    "n", "nonce",                "1", "Nonce",
    "d", "use_df",               "0", "Use derive function. Default: do not use derive function",
    "l", "entropy_input_length", "1", "Entropy Input length in bits",
    "k", "nonce_length",         "1", "Nonce Input length in bits",
    "h", "help",               "0", "This help"
  };
  static int nopts = sizeof(cmds)/(4*sizeof(char *));
  struct option long_options[nopts];
  char short_options[1+nopts*2];
  int c,i,j;
  char *char_ptr[3] = { NULL, NULL, NULL };
  char *char_ptr_dumy;
  unsigned int u_int;

  NIST_CTR_DRBG ctr_drbg ;   //Internal state of CTR_DRBG
  int entropy_input_length=0; //NIST_BLOCK_SEEDLEN_BYTES;
  int nonce_length = 0;
  int use_df=0; //False
  unsigned char entropy_input[NIST_BLOCK_SEEDLEN_BYTES];
  unsigned char entropy_reseed[NIST_BLOCK_SEEDLEN_BYTES];
  unsigned char nonce[NIST_BLOCK_SEEDLEN_BYTES];

  strcpy(short_options,"");
  for(i=j=0;i<nopts;i++,j+=4) {
    long_options[i].name      = cmds[j+1];
    long_options[i].has_arg   = atoi(cmds[j+2]);
    long_options[i].flag      = NULL;
    long_options[i].val       = cmds[j][0];
    strcat(short_options,cmds[j]);
    if (long_options[i].has_arg!=0) strcat(short_options,":");
  }

  do {
    c = getopt_long (argc, argv, short_options, long_options, NULL);
    switch(c) {
      case 'e':
        char_ptr[0] = optarg;
        break;
      case 'r':
        char_ptr[1] = optarg;
        break;
      case 'n':
        char_ptr[2] = optarg;
        break;
      case 'd':
        use_df = 1;
        break;
      case 'l':
        entropy_input_length = atoi(optarg) / 8;
      case 'k':
        nonce_length = atoi(optarg) / 8;
      case '?':
      case 'h':
        //usage(nopts, long_options, cmds);
      case -1:
        break;
    }
  } while (c!=-1);

  if ( nonce_length == 0 || entropy_input_length == 0 ) {
    fprintf(stderr, "Both nonce_length and entropy_input_length has to be specified!\n");
    exit(1);
  }

  if ( char_ptr[0] != NULL ) {
    char_ptr_dumy = char_ptr[0];
    for(i=0;i<entropy_input_length;++i) {
      j = sscanf(char_ptr_dumy, "%02x", &u_int);
      if ( j != 1 ) {
        fprintf(stderr, "Error during sscanf\n");
        fprintf(stderr, "Read %d bytes\n",j);
        fprintf(stderr, "%x", u_int);
        //exit(1);
      }
      entropy_input[i] = (unsigned char) u_int;
      char_ptr_dumy = char_ptr_dumy + 2;
    }
    //fwrite(entropy_input, entropy_input_length, 1,stdout);
    dump_hex_byte_string(entropy_input, entropy_input_length, "entropy_input: \t");
  }

  if ( char_ptr[1] != NULL ) {
    char_ptr_dumy = char_ptr[1];
    for(i=0;i<entropy_input_length;++i) {
      j = sscanf(char_ptr_dumy, "%02x", &u_int);
      if ( j != 1 ) {
        fprintf(stderr, "Error during sscanf\n");
        fprintf(stderr, "Read %d bytes\n",j);
        fprintf(stderr, "%x", u_int);
        //exit(1);
      }
      entropy_reseed[i] = (unsigned char) u_int;
      char_ptr_dumy = char_ptr_dumy + 2;
    }
    //fwrite(entropy_reseed, entropy_input_length, 1,stdout);
    dump_hex_byte_string(entropy_reseed, entropy_input_length, "entropy_reseed: \t");
  }

  if ( char_ptr[2] != NULL ) {
    char_ptr_dumy = char_ptr[2];
    for(i=0;i<nonce_length;++i) {
      j = sscanf(char_ptr_dumy, "%02x", &u_int);
      if ( j != 1 ) {
        fprintf(stderr, "Error during sscanf\n");
        fprintf(stderr, "Read %d bytes\n",j);
        fprintf(stderr, "%x", u_int);
        //exit(1);
      }
      nonce[i] = (unsigned char) u_int;
      char_ptr_dumy = char_ptr_dumy + 2;
    }
    //fwrite(nonce, 8, 1,stdout);
    dump_hex_byte_string(nonce, 8, "nonce: \t");
  }

  int number_of_chars;
  

  //memset(entropy_input, 0, sizeof(entropy_input));
  //read from stdin (fd 0)
  //number_of_chars  = read_data(0,entropy_input, entropy_input_length);

  //511 samples 128 bit long = 8176 BYTES
  const int output_string_length=16;
  unsigned char output_string[output_string_length];
  int error;

  error = nist_ctr_initialize();
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_initialize has returned %d\n",error);
    exit(error);
  }
 
  //dump_hex_byte_string (entropy_input, NIST_BLOCK_SEEDLEN_BYTES, "Input:\t\t");
/*
nist_ctr_drbg_instantiate(NIST_CTR_DRBG* drbg,
	const void* entropy_input, int entropy_input_length,
	const void* nonce, int nonce_length,
	const void* personalization_string, int personalization_string_length,
        int derive_function)
*/

  error = nist_ctr_drbg_instantiate(&ctr_drbg, entropy_input,  entropy_input_length, nonce, nonce_length, NULL, 0, use_df);
  if ( error ) {
    fprintf(stderr, "Error: nist_ctr_drbg_instantiate has returned %d\n",error);
    exit(error);
  }

  dump_hex_byte_string ((unsigned char*) ctr_drbg.ctx.key.rd_key, NIST_BLOCK_KEYLEN_BYTES, "Key:\t\t");
  dump_hex_byte_string ((unsigned char*) ctr_drbg.V, NIST_BLOCK_OUTLEN_BYTES, "Vector:\t\t");

  if (ctr_drbg.derive_function != 0) {
	  fprintf(stderr,"CTR DRBG, AES128, no prediction resistance, with derive function.\n");
  } else {
 	  fprintf(stderr,"CTR DRBG, AES128, no prediction resistance, without derive function.\n");
  }
  fprintf(stderr, "Reading entropy data from stdin and writing generating PRNG to stdout. For each 256 bits readed, 128*511=65408 bits will be generated.\n");

  nist_ctr_drbg_generate(&ctr_drbg, output_string, 16, NULL, 0);
  dump_hex_byte_string ((unsigned char*) ctr_drbg.ctx.key.rd_key, NIST_BLOCK_KEYLEN_BYTES, "Key:\t\t");
  dump_hex_byte_string ((unsigned char*) ctr_drbg.V, NIST_BLOCK_OUTLEN_BYTES, "Vector:\t\t");
  dump_hex_byte_string(output_string, 16, "output_string: \t");
  dump_hex_byte_string(entropy_reseed, entropy_input_length, "entropy_reseed: \t");
  nist_ctr_drbg_reseed(&ctr_drbg, entropy_reseed, entropy_input_length, NULL, 0);
  dump_hex_byte_string ((unsigned char*) ctr_drbg.ctx.key.rd_key, NIST_BLOCK_KEYLEN_BYTES, "Key:\t\t");
  dump_hex_byte_string ((unsigned char*) ctr_drbg.V, NIST_BLOCK_OUTLEN_BYTES, "Vector:\t\t");
  memset(output_string,0,16);
  dump_hex_byte_string(output_string, 16, "output_string: \t");
  sleep(2);
  nist_ctr_drbg_generate(&ctr_drbg, output_string, 16, NULL, 0);
  //fwrite(output_string, 16, 1,stdout);
  dump_hex_byte_string(output_string, 16, "output_string: \t");
  return(0);
  //Main loop

  while(1) {

    number_of_chars  = read_data(0,entropy_input, entropy_input_length);
    if ( number_of_chars<entropy_input_length) {
       fprintf(stderr, "Error: not enough data on the input, closing");
       exit(1);
    }
    
    //Generate upto 511 samples 128 bit long, 511*16= 8176 bytes
    error = nist_ctr_drbg_generate(&ctr_drbg, output_string, output_string_length, NULL, 0);
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_generate has returned %d\n",error);
      exit(error);
    }
    
    //Write random bytes to output, stdout=1
    //write(1, output_string,output_string_length);
    fwrite(output_string, output_string_length, 1,stdout);
    
    //Reseed
    error = nist_ctr_drbg_reseed(&ctr_drbg, entropy_input, entropy_input_length, NULL, 0);
    if ( error ) {
      fprintf(stderr, "Error: nist_ctr_drbg_reseed has returned %d\n",error);
      exit(error);
    }
  }

}
  
