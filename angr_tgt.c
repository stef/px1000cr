#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "utils.h"

static unsigned char lookupTable[31]={ // at 0xFEDB
   0x0B, 0x0A, 0x78, 0x0C, 0xE0, 0x29, 0x7B, 0xCF,
   0xC3, 0x4B, 0x2B, 0xCC, 0x82, 0x60, 0x80, 0x06,
   // from here on the table repeats its values, allowing for an easy
   // way to avoid rotate the values of this table based on the round
   // counter. just index starting from round_counter
   0x0B, 0x0A, 0x78, 0x0C, 0xE0, 0x29, 0x7B, 0xCF,
   0xC3, 0x4B, 0x2B, 0xCC, 0x82, 0x60, 0x80};

static unsigned char invertLoNibble2High(unsigned char x) {
  return ((x ^ 0xf) << 4) | x;
}


void lfsr(unsigned char state[16], unsigned char newstate[16]) {
  char round_counter; // at 0x5c
  unsigned char acc, i, tmp;

  // advance lfsrs
  for(round_counter = 0x1f;round_counter>=0;round_counter--) {                                        // lfsrs are iterated 32 times
    unsigned char off = (round_counter & 0xf); // offset, table shifts by one every iteration

    acc = 0;
    for(i=0;i<16;i++) { // FAC7 in the code this loop is unrolled
      acc ^= state[i] & lookupTable[off+i];
    } // FB43

    acc = ((acc >> 1) ^ acc) & 0x55; // FB45..FB4A

    // (*round_counter ^ 0xff) & 0xf == is twice the sequence 15..0
    tmp=(round_counter ^ 0xff) & 0xf;
    // (since the round_counter goes from 31..0, hence twice)
    state[tmp] = ((state[tmp] << 1) & 0xAA) | acc;
  } // FB63
  for(i=0;i<16;i++) newstate[i]=state[i];
}

void init_state(const char key[16], unsigned char state[16]) {
  // initialize LFSRs
  int i;
  for(i=0;i<15;i++) { // FA9E                                                                           // only 60 bits of entropy
    state[i] = invertLoNibble2High(key[i]);
  }
  state[15]=0xff; // FAB0..FAB4                                                                          // not sure why this has to be 0xff, the other bytes are all also guaranteed to not be all == 0
}

uint32_t extract_lfsr(unsigned char state[16]) {
  int i;
  unsigned char tmp;
  unsigned char lfsr_out[4]; // at 0x82
  for(i=0;i<4;i++) {
    tmp = state[i+7]; // FB68..FB6C
    tmp = (tmp << 2) | (tmp >> 6); // 2x rotate left FB6E..FB72                                     // lfsr_out[i] = rol(lfsr[i+7], 2) ^ lfsr[i]
    lfsr_out[i] = tmp ^ state[i]; // FB74 .. FB7A                                                    // lfsr_out[0] = rol(lfsr[7],2) ^ lfsr[0]
  }
  return *((uint32_t*) lfsr_out);
}

int main(void) {
  unsigned char state[16];
  init_state("\x00\x08\x02\x0e\x0f\x09\x0c\x07\x0a\x03\x02\x02\x09\x0d\x0c\x0f", state);
  hexdump("lfsr0", state,16);
  unsigned char newstate[16];
  lfsr(state, newstate);
  hexdump("lfsr1", newstate,16);
  printf("%08x\n",extract_lfsr(newstate));
  //printf("%08x\n",lfsr("\x00\x08\t\x00\x04\t\n\x05\x00\x0c\x02\x08\x0c\n\x08\x00"));
  return 0;
}
