#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "core.h"

int main(const int argc, const char *argv[]) {
  if(argc!=2) return 1;
  if(strlen(argv[1])!=16) {
    fprintf(stderr, "first param must be 16B key string\n");
    return 1;
  }
  char ciphertext[8192];
  size_t ctlen=fread(ciphertext,1,8192,stdin);;
  char key[16];
  int i;
  // truncate input key
  for(i=0;i<16; i++) key[i] = argv[1][i] & 0x0f;

  px1kcr(ciphertext+1, ctlen, decrypt, key);

  fwrite(ciphertext+1, ctlen-2, 1, stdout);

  return 0;
}
