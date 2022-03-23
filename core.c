#include "core.h"
#include <stdio.h>

static unsigned char lookupTable[31]={ // at 0xFEDB
   0x0B, 0x0A, 0x78, 0x0C, 0xE0, 0x29, 0x7B, 0xCF,
   0xC3, 0x4B, 0x2B, 0xCC, 0x82, 0x60, 0x80, 0x06,
   // from here on the table repeats its values, allowing for an easy
   // way to avoid rotate the values of this table based on the round
   // counter. just index starting from round_counter
   0x0B, 0x0A, 0x78, 0x0C, 0xE0, 0x29, 0x7B, 0xCF,
   0xC3, 0x4B, 0x2B, 0xCC, 0x82, 0x60, 0x80};

static unsigned char lookupTable6To1bit[64]={ // at 0xFE9B
   0x96, 0x4b, 0x65, 0x3a, 0xac, 0x6c, 0x53, 0x74,
   0x78, 0xa5, 0x47, 0xb2, 0x4d, 0xa6, 0x59, 0x5a,
   0x8d, 0x56, 0x2b, 0xc3, 0x71, 0xd2, 0x66, 0x3c,
   0x1d, 0xc9, 0x93, 0x2e, 0xa9, 0x72, 0x17, 0xb1,
   0xb4, 0xe4, 0xa3, 0x4e, 0x27, 0x5c, 0x8b, 0xc5,
   0xe8, 0x95, 0xe1, 0xd1, 0x87, 0xb8, 0x1e, 0xca,
   0x1b, 0x63, 0xd8, 0x2d, 0xd4, 0x9a, 0x99, 0x36,
   0x8e, 0xc6, 0x69, 0xe2, 0x39, 0x35, 0x6a, 0x9c
};

static unsigned char map4to4bit[4][16]={ // 0xfe5b
   {0x6, 0xA, 0x1, 0x2, 0xE, 0x7, 0x8, 0x9,
    0xC, 0x4, 0x3, 0xF, 0xB, 0x0, 0x5, 0xD},
   {0x2, 0x7, 0x0, 0x5, 0xF, 0x3, 0x1, 0x9,
    0xE, 0xD, 0xB, 0x8, 0xC, 0xA, 0x4, 0x6},
   {0x9, 0x1, 0x3, 0xC, 0x2, 0x0, 0xA, 0xE,
    0xD, 0x6, 0xB, 0x7, 0x5, 0x8, 0xF, 0x4},
   {0xB, 0x6, 0x9, 0x0, 0x5, 0xE, 0xF, 0x8,
    0x4, 0xC, 0x1, 0xD, 0x2, 0x7, 0x3, 0xA}
};

static unsigned char invertLoNibble2High(unsigned char x) {
  return ((~x) << 4) | x;
}

void hexdump(const char* msg, const unsigned char* ptr, const size_t len) {
  //return;
  size_t i;
  printf("%s ", msg);
  for(i=0;i<len;i++) {
    if(i && (i%16==0)) printf("\n\t");
    printf("%02x ", ptr[i]);
  }
  printf("\n");
}

void px1kcr(char *plaintext, const int ptlen, const CryptMode EncryptorDecryptMode, const char truncated_input_key[16]) {
  int curChar = -1;
  unsigned char acc; // stored at 0x5a
  char round_counter; // at 0x5c
  unsigned char initial_key[8]; // stored at 0x74
  unsigned char CiphertextFifo[5]; // stored directly after initial_key at 0x7d
                                   // is really just 4 bytes, the last one is for
                                   // shifting in.
                                   // also note this bleeding from External Memory
                                   // into Internal RAM segments. which is strange
  unsigned char lfsr_out[4]; // at 0x82
  unsigned char pbuf[4]; // at 0x86
  unsigned char lfsr[16]; // stored at 0x8A
  unsigned char i, j, tmp;

  // fa63
  // initialize V & Ciphertext FIFO
  for(i=0;i<4;i++) {
    initial_key[i]   = invertLoNibble2High(truncated_input_key[i]   ^ truncated_input_key[i+4]);
    initial_key[i+4] = invertLoNibble2High(truncated_input_key[i+8] ^ truncated_input_key[i+12]);
    CiphertextFifo[i] = initial_key[i] ^ initial_key[i+4] ^ 0xf0;
  } // FA8B
  hexdump("V", initial_key, 8);
  // FA9C
  hexdump("CTFifo", CiphertextFifo, 4);

  // initialize LFSRs
  for(i=0;i<15;i++) { // FA9E
    lfsr[i] = invertLoNibble2High(truncated_input_key[i]);
  }
  lfsr[15]=0xff; // FAB0..FAB4
  hexdump("lfsr", lfsr, 16);

  for(curChar=-1;curChar<ptlen;curChar++) {
    // advance lfsrs
    for(round_counter = 0x1f;round_counter>=0;round_counter--) {
      acc = 0;
      for(i=0;i<16;i++) { // FAC7 in the code this loop is unrolled
        acc ^= lfsr[i] & lookupTable[(round_counter+i)%16];
      } // FB43

      acc = ((acc >> 1) ^ acc) & 0x55; // FB45..FB4A

      // (round_counter ^ 0xff) & 0xf == is twice the sequence 15..0
      tmp=(round_counter ^ 0xff) & 0xf;
      // (since the round_counter goes from 31..0, hence twice)
      lfsr[tmp] = ((lfsr[tmp] << 1) & 0xAA) | acc;
    } // FB63
    hexdump("lfsr", lfsr, 16);

    // update pbuf (according to cm)
    for(i=0;i<4;i++) {
      tmp = lfsr[i+7]; // FB68..FB6C
      tmp = (tmp << 2) | (tmp >> 6); // 2x rotate left FB6E..FB72
      lfsr_out[i] = tmp ^ lfsr[i]; // FB74 .. FB7A

      tmp = initial_key[i] ^ CiphertextFifo[i];
      // cheating here, fb85 says fe4b, but after shifting be its at least 16,
      // which points to map4to4bit
      printf("v[%d]", i);
      hexdump("",&initial_key[i],1);
      printf("ct[%d]", i);
      hexdump("",&CiphertextFifo[i],1);
      hexdump("tmp",&tmp,1);
      acc = map4to4bit[i][tmp >> 4] << 4;
      acc |= map4to4bit[i][tmp & 0xf];
      hexdump("acc",&acc,1);
      printf("v[%d]", i+4);
      hexdump("",&initial_key[i+4],1);
      pbuf[i] = acc ^ initial_key[i+4];
    }
    hexdump("lfsr_out", lfsr_out, 4);
    hexdump("pbuf", pbuf, 4);

    // FBB5
    for(i=8, acc=0;i>0;i--) {
      // FBB9
      printf("%d: ",i-i);
      for(j=1,tmp=0;j<4;j++) {
        printf("%d", (lfsr_out[j] >> 7));
        tmp = (tmp << 1) | (lfsr_out[j] >> 7);
        lfsr_out[j]<<=1;
        printf("%d", (pbuf[j] >> 7));
        tmp = (tmp << 1) | (pbuf[j] >> 7);
        pbuf[j]<<=1;
      }
      printf("\n%02x->", tmp);
      tmp=lookupTable6To1bit[tmp];
      printf("%d\n", ((tmp>>(i-1)) & 1));

      acc=(acc<<1) + ((tmp>>(i-1)) & 1); // rotate acc left and add the Ith bit of tmp
    } // 0xfbd9
    hexdump("F()", &acc,1);

    printf("pbuf[0] == %02x, lfsr_out[0] == %02x\n", pbuf[0], lfsr_out[0]);
    acc ^= pbuf[0] ^ lfsr_out[0]; // 0xFBDD

    // FBDF
    printf("k0: %02x\n",acc);

    tmp = (curChar + 1) & 7;
    printf("rot: %d\n", tmp);
    acc = (acc << tmp) | (acc >> (8-tmp)); // rotate left by tmp

    printf("k: %02x\n", acc);

    tmp = plaintext[curChar];
    plaintext[curChar] ^= acc;

    if(EncryptorDecryptMode == encrypt) {
      tmp = plaintext[curChar];
    }
    // tmp contains the ciphertext byte (according to the cm webpage)
    // FC05
    CiphertextFifo[4] = tmp;
    for(i=0;i<4;i++) {
      // rot left
      CiphertextFifo[i] = (CiphertextFifo[i+1] << 1) | (CiphertextFifo[i+1] >> 7);
    } // FC15
    hexdump("CTFIFO[n+1]",CiphertextFifo,4);
  }
  // todo EOStringToEncrypt()
}
