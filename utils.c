#include <stdio.h>
#include <string.h>

void hexdump(const char* msg, const unsigned char* ptr, const size_t len) {
  size_t i;
  printf("%s ", msg);
  for(i=0;i<len;i++) {
    if(i && (i%16==0)) printf("\n\t");
    printf("%02x ", ptr[i]);
  }
  printf("\n");
}

const char *bit_rep[16] = {
    [ 0] = "0000", [ 1] = "0001", [ 2] = "0010", [ 3] = "0011",
    [ 4] = "0100", [ 5] = "0101", [ 6] = "0110", [ 7] = "0111",
    [ 8] = "1000", [ 9] = "1001", [10] = "1010", [11] = "1011",
    [12] = "1100", [13] = "1101", [14] = "1110", [15] = "1111",
};

static void print_byte(const unsigned char byte) {
    printf("%s%s", bit_rep[byte >> 4], bit_rep[byte & 0x0F]);
}

void bindump(const unsigned char *ptr, const size_t len) {
  size_t i;
  for(i=0;i<len;i++) {
    print_byte(ptr[i]);
  }
  printf("\n");
}

void extractA(const unsigned char lfsr[16], unsigned char lfsrs[4][4]) {
  // takes 2 bits from each byte and concats them
  // down-then-right direction
  int i;
  for(i=0;i<16;i++) {
    lfsrs[0][i/4]|=((lfsr[i] >> 0) & 0x3) << ((i%4)*2);
    lfsrs[1][i/4]|=((lfsr[i] >> 2) & 0x3) << ((i%4)*2);
    lfsrs[2][i/4]|=((lfsr[i] >> 4) & 0x3) << ((i%4)*2);
    lfsrs[3][i/4]|=((lfsr[i] >> 6) & 0x3) << ((i%4)*2);
  }
}

void extractB(const unsigned char lfsr[16], unsigned char lfsrs[4][4]) {
  // right-then down
  int i;
  for(i=0;i<16;i++) {
    lfsrs[0][i/8]|=(lfsr[i] & 1) << (i%8);
    lfsrs[0][2+i/8]|=((lfsr[i] >> 1) & 1) << (i%8);

    lfsrs[1][i/8]|=((lfsr[i] >> 2) & 1) << (i%8);
    lfsrs[1][2+i/8]|=((lfsr[i] >> 3) & 1) << (i%8);

    lfsrs[2][i/8]|=((lfsr[i] >> 4) & 1) << (i%8);
    lfsrs[2][2+i/8]|=((lfsr[i] >> 5) & 1) << (i%8);

    lfsrs[3][i/8]|=((lfsr[i] >> 6) & 1) << (i%8);
    lfsrs[3][2+i/8]|=((lfsr[i] >> 7) & 1) << (i%8);
  }
}

unsigned char prev[16]={0};
int bindiff(const unsigned char *ptr, const int len) {
  int i, j, tot=0;
  for(i=0;i<len;i++) {
    for(j=7;j>-1;j--) {
      if((prev[i] ^ ptr[i]) & (1 << j)) {
        printf("\x1b[3;30;43m%d\x1b[0m", (ptr[i] >> j) & 1);
        tot++;
      } else {
        printf("%d", (ptr[i] >> j) & 1);
      }
    }
  }
  printf(" %d \n", tot);
  memcpy(prev,ptr,len);
  return tot;
}

#ifdef TEST
int main(void) {
  unsigned char lfsrs[4][4]={0};
  {
    unsigned char lfsr[16] = { 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 };
    memset(lfsrs,0,16);
    extractA(lfsr,lfsrs);
    const unsigned char expected[16]={0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractA({3,3,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
    extractB(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractB({3,3,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
  }
  {
    memset(lfsrs,0,16);
    unsigned char lfsr[16] = {12,12,12,12,12,12,12,12,12,12,12,12,12,12,12,12};
    extractA(lfsr,lfsrs);
    const unsigned char expected[16]={ 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0};
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractA({c,c,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
    extractB(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractB({c,c,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
  }
  {
    memset(lfsrs,0,16);
    unsigned char lfsr[16] = {0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30};
    const unsigned char expected[16]={ 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0};
    extractA(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractA({0x30,0x30,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
    extractB(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractB({0x30,0x30,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
  }
  {
    memset(lfsrs,0,16);
    unsigned char lfsr[16] = {0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0 };
    const unsigned char expected[16]={0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
    extractA(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractA({0xc0,0xc0,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
    extractB(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractB({0xc0,0xc0,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
  }
  {
    memset(lfsrs,0,16);
    unsigned char lfsr[16] = {0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0xc3};
    const unsigned char expected[16]={0xff, 0xff, 0xff, 0xff , 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff};
    extractA(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractA({0xc3,0xc3,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
    extractB(lfsr,lfsrs);
    if(memcmp(expected, lfsrs,16)!=0) {
      printf("extractB({0xc3,0xc3,...}) failed\n");
      hexdump("expected: ", expected,16);
      hexdump("fail: ", lfsrs[0],16);
      return 1;
    }
  }

  {
    memset(lfsrs,0,16);
    unsigned char lfsr[16] = {0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81};
    extractA(lfsr,lfsrs);
    {
      const unsigned char expected[16]={0x55, 0x55, 0x55, 0x55 , 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa, 0xaa, 0xaa};
      if(memcmp(expected, lfsrs,16)!=0) {
        printf("extractA({0x81,0x81,...}) failed\n");
        hexdump("expected: ", expected,16);
        hexdump("fail: ", lfsrs[0],16);
        return 1;
      }
    }
    memset(lfsrs,0,16);
    {
      const unsigned char expected[16]={0xff, 0xff, 0x00, 0x00 , 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0xff, 0xff};
      extractB(lfsr,lfsrs);
      if(memcmp(expected, lfsrs,16)!=0) {
        printf("extractB({0x81,0x81,...}) failed\n");
        hexdump("expected: ", expected,16);
        hexdump("fail: ", lfsrs[0],16);
        return 1;
      }
    }
  }

  return 0;
}
#endif
