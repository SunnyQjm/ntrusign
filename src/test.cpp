#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <dlfcn.h>
#include "fftw3.h"
#ifdef __cplusplus 
extern "C"{
#endif
#include <mytest/constants.h>
#include <mytest/pass_types.h>

#include <mytest/bsparseconv.h>
#include <mytest/crypto_hash_sha512.h>
#include <mytest/crypto_stream_salsa20.h>
#include <mytest/fastrandombytes.h>
#include <mytest/formatc.h>
#include <mytest/hash.h>
#include <mytest/ntt.h>
#include <mytest/pass.h>

#include <mytest/poly.h>
#include <mytest/randombytes.h>
int gen_key(int64 *f);
#ifdef __cplusplus 
}
#endif
using namespace std;
#ifndef VERIFY
#define VERIFY 1
#endif

#ifndef TRIALS
#define TRIALS 10000
#endif

#define MLEN 8000


int
main(int argc, char **argv)
{
  int i;
  int count;

  int64 key[PASS_N];
  int64 *z;
  unsigned char in[MLEN+1] = {0};
  unsigned char h[HASH_BYTES];

  memset(in, '0', MLEN);
  z = reinterpret_cast<int64 *>(malloc(PASS_N * sizeof(int64)));
  if(z==NULL) {
    fprintf(stderr,"ERROR: Could not allocate memory.\n");
    exit(EXIT_FAILURE);
  }

  init_fast_prng();

  if(ntt_setup() == -1) {
    fprintf(stderr,
        "ERROR: Could not initialize FFTW. Bad wisdom?\n");
    exit(EXIT_FAILURE);
  }

  printf("Parameters:\n\t N: %d, p: %d, g: %d, k: %d, b: %d, t: %d\n\n",
      PASS_N, PASS_p, PASS_g, PASS_k, PASS_b, PASS_t);

  printf("Generating %d signatures %s\n", TRIALS,
          VERIFY ? "and verifying" : "and not verifying");

  gen_key(key);

#if DEBUG
  printf("sha512(key): ");
  crypto_hash_sha512(h, (unsigned char*)key, sizeof(int64)*PASS_N);
  for(i=0; i<HASH_BYTES; i++) {
    printf("%.2x", h[i]);
  }
  printf("\n");
#endif

#if VERIFY
  int nbver = 0;

  int64 pubkey[PASS_N] = {0};
  gen_pubkey(pubkey, key);
#endif

  clock_t c0,c1;
  c0 = clock();

  
  count = 0;
  for(i=0; i<TRIALS; i++) {
   printf("this is the location of message: %d,and this is trials: %d\n",i&0xffff,i);
   //in[(i&0xff)]++; /* Hash a different message each time */
   printf("this is the unhashed message: %s\n",in);
   count += sign(h, z, key, in, MLEN);
   //this is modified by yb
   
   

#if VERIFY
   nbver += (VALID == verify(h, z, pubkey, in, MLEN));
#endif
  }
  printf("\n");

  c1 = clock();

  printf("this is the key: ");
  printf("%64ld\n",key);
  printf("this is the public key: ");
  printf("%64ld\n",pubkey);

  printf("Total attempts: %d\n",  count);
#if VERIFY
  printf("Valid signatures: %d/%d\n",  nbver, TRIALS);
#endif
  printf("Attempts/sig: %f\n",  (((float)count)/TRIALS));
  printf("Time/sig: %fs\n", (float) (c1 - c0)/(TRIALS*CLOCKS_PER_SEC));

#if DEBUG
  printf("\n\nKey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) key[i]));

  #if VERIFY
  printf("\n\nPubkey: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) pubkey[i]));
  printf("\n");
  #endif

  printf("\n\nz: ");
  for(i=0; i<PASS_N; i++)
    printf("%lld, ", ((long long int) z[i]));
  printf("\n");
#endif

  free(z);
  ntt_cleanup();
  return 0;
}

