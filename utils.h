#ifndef UTILS_H
#define UTILS_H
#include <stdlib.h>

void hexdump(const char* msg, const unsigned char* ptr, const size_t len);
void bindump(unsigned char *ptr, const size_t len);
void extractA(const unsigned char lfsr[16], unsigned char lfsrs[4][4]);
void extractB(const unsigned char lfsr[16], unsigned char lfsrs[4][4]);
int bindiff(const unsigned char *ptr, const int len);
#endif
