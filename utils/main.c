/* Simple main program 

   
src/csprng | dd of=/dev/null bs=4096 count=100000
src/csprng | pv > /dev/null
src/csprng | /home/jirka/C/64-bit/2011-Jan-20-dieharder/dieharder-3.31.0_BIN/bin/dieharder -g 200 -a

/home/jirka/C/64-bit/2011-Sep-16-HAVEGED/New_official_release/2011-Oct-20/haveged-1.3/src/haveged -n0 | dd of=/dev/null bs=4096 count=100000

*/


#include <stdlib.h>
#include <stdio.h>

#include <csprng/csprng.h>


int main(int argc, char **argv) {
  int error;
  csprng_state_type csprng_state;
  unsigned char *output_buffer;
  int output_buffer_size = 512*16;

  output_buffer	= (unsigned char*) malloc ( output_buffer_size * sizeof(unsigned char) );
  if ( output_buffer ==NULL ) {
    fprintf ( stderr, "\nDynamic memory allocation failed\n" );
    return (1);
  } 

  error = csprng_init(&csprng_state, 0, 0);
  if ( error ) {
    fprintf(stderr, "Error: csprng_init has returned %d\n",error);
    return(error);
  }


  while(1) {
    error = csprng_generate(&csprng_state, output_buffer, output_buffer_size);
    if ( error ) {
      fprintf(stderr, "Error: csprng_generate  has returned %d\n",error);
      return(error);
    }
    fwrite (output_buffer, sizeof(unsigned char), output_buffer_size, stdout);
  }

  error = csprng_destroy(&csprng_state);
  if ( error ) {
    fprintf(stderr, "Error: csprng_destroy has returned %d\n",error);
    return(error);
  }

  return(EXIT_SUCCESS);
}
