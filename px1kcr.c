#include <stdio.h>
#include <string.h>

static unsigned char lookupTable[31]={ // at 0xFEDB
   0x0B, 0x0A, 0x78, 0x0C, 0xE0, 0x29, 0x7B, 0xCF,
   0xC3, 0x4B, 0x2B, 0xCC, 0x82, 0x60, 0x80, 0x06,
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

static unsigned char lookup6to4bit[4][16]={ // 0xfe5b
   {0x6, 0xA, 0x1, 0x2, 0xE, 0x7, 0x8, 0x9,
    0xC, 0x4, 0x3, 0xF, 0xB, 0x0, 0x5, 0xD},
   {0x2, 0x7, 0x0, 0x5, 0xF, 0x3, 0x1, 0x9,
    0xE, 0xD, 0xB, 0x8, 0xC, 0xA, 0x4, 0x6},
   {0x9, 0x1, 0x3, 0xC, 0x2, 0x0, 0xA, 0xE,
    0xD, 0x6, 0xB, 0x7, 0x5, 0x8, 0xF, 0x4},
   {0xB, 0x6, 0x9, 0x0, 0x5, 0xE, 0xF, 0x8,
    0x4, 0xC, 0x1, 0xD, 0x2, 0x7, 0x3, 0xA}
};

// in the ROM this is inverted at 0xFA5D in the backdoored function causing some confusion
// it seems however outside of this function to serve as a flag which op can be done on the string
typedef enum {decrypt = 0, encrypt = 0x80} CryptMode;

static unsigned char invertLoNibble2High(unsigned char x) {
  return ((x ^ 0xf) << 4) | x;
}

static void backdoored(char *startOfString, const char *EOString, const CryptMode EncryptorDecryptMode, const char truncated_input_key[16]) {
  char *CurCharLocation = startOfString-1; // at 0x2d
  char round_counter; // at 0x5c

  unsigned char lfsr_out[4]; // at 0x82
  unsigned char pbuf[4]; // at 0x86
  unsigned char initial_key[8]; // stored at 0x74
  unsigned char i, tmp;
  // not sure why there is two loops here initializing initial_key
  // when this could've been just one?
  // fa63
  // initialize Va
  for(i=0;i<4;i++) {
    tmp = truncated_input_key[i] ^ truncated_input_key[i+4];
    initial_key[i] = invertLoNibble2High(tmp);
  }
  // initialize Vb
  for(i=0;i<4;i++) {                                                // coincidentally, when t_i_k is 0..16
    tmp = truncated_input_key[i+8] ^ truncated_input_key[i+12];     // then initial_key will be 8 times the value b4
    initial_key[i+4] = invertLoNibble2High(tmp);
  } // FA8B

  // FA8D
  unsigned char CiphertextFifo[5]; // stored directly after initial_key at 0x7d
  // is really just 4 bytes, the last one is for
  // shifting in.
  // also note this bleeding from External Memory
  // into Internal RAM segments. which is strange
  // initialize FIFO C
  for(i=0;i<4;i++) {                                                // if initial_key[n] == initial_key[n+4],
    CiphertextFifo[i] = initial_key[i] ^ initial_key[4+i] ^ 0xf0;   // then the fifo value is 0!
  }                                                                 // which is the case when t_i_k = 0..16
  // FA9C

  // FA9E
  unsigned char lfsr[16]; // stored at 0x8A
  // lsfr taps (source unknown)
  // 27b 27,5,2,1
  // 29b 29,27
  // 31b 31,28
  // 32b 32,22,2,1
  // initialize LFSRs
  for(i=0;i<15;i++) {
    lfsr[i] = invertLoNibble2High(truncated_input_key[i]);
  }
  lfsr[15]=0xff; // FAB0..FAB4

  char acc; // stored at 0x5a
  while(EOString > CurCharLocation) {
    for(round_counter = 0x1f;round_counter>=0;round_counter--) {
      unsigned char *lookupOffset = lookupTable + (round_counter & 0xf);

      acc = lfsr[0] & lookupOffset[0]; // FAC7 .. FACB
      for(i=1;i<16;i++) { // FACD in the code this loop is unrolled
        acc ^= lfsr[i] & lookupOffset[i];
      } // FB43

      acc = ((acc >> 1) ^ acc) & 0x55; // FB45..FB4A

      // (*round_counter ^ 0xff) & 0xf == is twice the sequence 15..0
      // (since the round_counter goes from 31..0, hence twice)
      lfsr[(round_counter ^ 0xff) & 0xf] = ((lfsr[(round_counter ^ 0xff) & 0xf] << 1) & 0xAA) | acc;
    } // FB63

    // update pbuf (according to cm)
    for(i=4;i>0;i--) {
      tmp = lfsr[(i-1)+7]; // FB68..FB6C
      tmp = (tmp << 2) | (tmp >> 6); // 2x rotate left FB6E..FB72
      lfsr_out[i-1] = tmp ^ lfsr[i-1]; // FB74 .. FB7A

      tmp = initial_key[i-1] ^ CiphertextFifo[i-1]; // wtf? initial key is only 8B
                                                    // initial_key[i+8] == CiphertextFifo[i]

      // cheating here, fb85 says fe4b, but after shifting be its at least 16,
      // which points to lookup6to4bit
      acc = lookup6to4bit[(i-1)][tmp >> 4] << 4;
      tmp = acc | lookup6to4bit[(i-1)][tmp & 0xf];
      pbuf[i-1] = tmp ^ initial_key[i+3];
    }

    unsigned char res;
    // FBB5
    for(i=8, res=0;i>0;i--) {
      // FBB9
      unsigned char b=0;
      char j;
      for(j=0;j<3;j++) {
        b = (b << 1) | (lfsr_out[1+j] >> 7);
        lfsr_out[1+j]<<=1;
        b = (b << 1) | (pbuf[1+j] >> 7);
        pbuf[1+j]<<=1;
      }
      unsigned char a=lookupTable6To1bit[b];

      res=(res<<1) + ((a>>(i-1)) & 1); // rotate res left and add the Ith bit of a
    } // 0xfbd9

    res ^= pbuf[0] ^ lfsr_out[0]; // 0xFBDD

    // FBDF

    tmp = ((CurCharLocation - startOfString) + 1) & 7;
    res = (res << tmp) | (res >> (8-tmp)); // rotate left by tmp

    tmp = *CurCharLocation;
    *CurCharLocation++ ^= res;

    if(EncryptorDecryptMode == encrypt) {
      tmp = *(CurCharLocation-1);
    }
    // tmp contains the ciphertext byte (according to the cm webpage)
    // FC05
    CiphertextFifo[4] = tmp;

    for(i=0;i<4;i++) {
      // rot left
      CiphertextFifo[i] = (CiphertextFifo[i+1] << 1) | (CiphertextFifo[i+1] >> 7);
    } // FC15
  }
  // todo EOStringToEncrypt()
}

int main(void) {
  // note the leading '(' char which indicates the "margin",
  // which is set by the PX1000 and is included in the ciphertext
  // the value of the margin must be between 10 and 80 inclusive.
  // also notice the trailing 0x8d, which is a newline with high bit
  // set to indicate the end of the string.

  //char string[]="(We have a working PX1000Cr emulator, and also a C version of the encryption algorithm.", *eos=string+strlen(string)-1;
  //char string[]="(test\x8d", *eos=string+strlen(string);
  char string[]="(testtesttesttesta\x8d", *eos=string+strlen(string);
  // "PX1000CrPassword"
  char key[16]={
                0x50, 0x58, 0x31, 0x30,
                0x30, 0x30, 0x43, 0x72,
                0x50, 0x61, 0x73, 0x73,
                0x77, 0x6f, 0x72, 0x64};
  int i;
  // truncate input key
  for(i=0;i<16; i++) key[i] &= 0x0f;
  backdoored(string+1, eos, encrypt, key);
  backdoored(string+1, eos, decrypt, key);
  printf("decrypted: '%s'\n", string+1);
  return 0;
}
