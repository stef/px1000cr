#ifndef core_h
#define core_h

#include <stdlib.h>

typedef enum {decrypt = 0, encrypt = 0x80} CryptMode;

void hexdump(const char* msg, const unsigned char* ptr, const size_t len);
void px1kcr(char *startOfString, const int ptlen, const CryptMode EncryptorDecryptMode, const char truncated_input_key[16]);

#endif
