There are two sets of RNG example files:

1. The response (.rsp) files contain properly formatted CAVS response files.

2. The intermediate value (.txt) files for the tests contain intermediate
   values.  The DRBG tests consist of the following four operations:
   i. Instantiate
   ii. Generate Random Bits
   iii. Generate Random Bits
   iv. Uninstantiate
   The response files contain all inputs for Instantiate and both calls to
   Generate and the Random Bits (i.e., ReturnedBits) returned from the second
   call to Generate.  The intermediate value (.txt) files also show the value
   of the working state after the first call to Generate and the Random Bits
   (ReturnedBits) returned from the first call to Generate.  These values
   are indented by one tab space and are labeled as 'INTERMEDIATE'.
   
The working state values printed out for the different DRBG mechanisms are:
1. Hash_DRBG - working state consists of 'V' and 'C'.
2. HMAC_DRBG - working state consists of 'V' and 'Key'.
3. CTR_DRBG - working state consists of 'V' and 'Key'.
4. Dual_EC_DRBG - the secret value of the working state is 's'.  Other elements
   of the working state, such as the curve domain parameters and points P and
   Q, are not secret.

Refer to NIST SP 800-90 for more on the DRBG mechanisms and their working state
variables:

http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf