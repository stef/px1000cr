#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "core.h"

static char* pad(const char* in) {
  // note the leading '(' char which indicates the "margin",
  // which is set by the PX1000 and is included in the ciphertext
  // the value of the margin must be between 10 and 80 inclusive.
  // also notice the trailing 0x8d, which is a newline with high bit
  // set to indicate the end of the string.
  size_t len = strlen(in);
  char *out = malloc(len+2);
  if(out==NULL) return NULL;
  out[0]='(';
  memcpy(out+1,in, len);
  out[len+1]=0x8d;
  return out;
}

int main(const int argc, const char *argv[]) {
  if(argc!=3) return 1;
  if(strlen(argv[1])!=16) {
    fprintf(stderr, "first param must be 16B key string\n");
    return 1;
  }
  size_t ptlen=strlen(argv[2]) + 2;
  char *plaintext=pad(argv[2]);
  char key[16];
  int i;
  // truncate input key
  for(i=0;i<16; i++) key[i] = argv[1][i] & 0x0f;
  px1kcr(plaintext+1, ptlen, encrypt, key);
  fwrite(plaintext, ptlen, 1, stdout);
  //hexdump("ciphertext", plaintext, ptlen);

  return 0;
}
