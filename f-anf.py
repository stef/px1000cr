#!/usr/bin/env python

moebius_c_output = """
0110001001101010101110001110101100101011011110001101001000101100 32
0110010100001111101101110100100101011011010010010011000110001110 32

1101001000110101011101100011011000111010000010111100010111010010 32
1011100010011110110010011100101110010110101111010100100111111110 38

1010110101101100110000111001001011011101010010100001100111000101 32
1100011110101011011011111110111001110111010000101100000010110110 37

0101110010001011101000011101100000010110100001111011011010101011 32
0100111010111100100000111100010101011001010100110100111100110000 31

1001001110010011010011011010011110000100010101101010111100001101 32
1110110000000000101100101001010100010110101110001000110011100010 27

0011110111010100001010110001110111101000101001000101000100111110 32
0010100110010111000101111011001110111111110010001100010010000010 32

0110011110101011010111100100010001010101101100010110100001110010 32
0110000110100000001011001011110100100001001111000000010100111100 26

1000100001010100100101000110100111100011111111010010111011010001 32
1111000010110001000110110011001001101011101010011011101010101010 33
"""

"""
generated by

#include <stdint.h>
#include <stdio.h>
#include <string.h>

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

// src sci-gems.math.bas.bg/jspui/bitstream/10525/2935/1/sjc-vol11-num1-2017-p045-p057.pdf
void moebius(uint8_t *f, int n) {
   int blocksize=1;
   int step;
   for(step=1; step<=n;step++) {
     int source=0;
     while(source < (1<<n)) {
         int target = source + blocksize;
         int i;
         for(i=0;i<blocksize;i++) {
            f[target+i]^=f[source+i];
         }
         source+=2*blocksize;
     }
     blocksize*=2;
   }
}

int main(void) {
  int i,j, ones;
  uint8_t f[8][64]={0};
  for(i=0;i<8;i++) {
    // initialize f
    for(j=0;j<64;j++) {
      f[i][j]=(lookupTable6To1bit[j] >> i) & 1;
    }
    ones=0;
    for(j=0;j<64;j++) {
      ones+=f[i][j];
      printf("%d",f[i][j]);
    }
    printf(" %d \n", ones);

    moebius(f[i],6);
    ones=0;
    for(j=0;j<64;j++) {
      ones+=f[i][j];
      printf("%d",f[i][j]);
    }
    printf(" %d \n\n", ones);
  }
  return 0;
}
"""


fs = [l.split()[0] for i, l in enumerate(moebius_c_output.split('\n')) if (i%3 == 1) and l]
moebiuses = [l.split()[0] for i, l in enumerate(moebius_c_output.split('\n')) if (i%3 == 2) and l]

for j, (f, moebius) in enumerate(zip(fs,moebiuses)):
    f_ = ' ^ '.join('('+c+')' for c in ['&'.join(f"x[{i}:{i}]" for i, x in enumerate(reversed(f'{a:06b}')) if x == "1") for a in range(64) if moebius[a]=='1'] if c)
    f__ = ' ^ '.join('('+c+')' for c in ['&'.join(f"x[{i}]" for i, x in enumerate(reversed(f'{a:06b}')) if x == "1") for a in range(64) if moebius[a]=='1'] if c)
    if j in [1,2,4,7]: # they have odd number of 1 constant terms in their polinomial
        f_ = '1 ^ ' + f_
        f__ = '1 ^ ' + f__
    print(f_)
    evaled =''.join(str(eval(f__, {'x': [int(x) for i, x in enumerate(reversed(f'{a:06b}'))]})) for a in range(64))
    assert evaled==f

"""
outputs

(x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[4:4]) ^ (x[1:1]&x[4:4]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[1:1]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
1 ^ (x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[4:4]) ^ (x[0:0]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
1 ^ (x[0:0]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[4:4]) ^ (x[1:1]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[1:1]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
(x[0:0]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[2:2]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4])
^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5])
1 ^ (x[0:0]) ^ (x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[2:2]) ^ (x[4:4]) ^ (x[1:1]&x[4:4]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
(x[1:1]) ^ (x[2:2]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[0:0]&x[2:2]&x[3:3]) ^ (x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[5:5]) ^ (x[1:1]&x[5:5]) ^ (x[0:0]&x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[0:0]&x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[0:0]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[0:0]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
(x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[1:1]&x[2:2]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[1:1]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[0:0]&x[2:2]&x[4:4]) ^ (x[3:3]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[1:1]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[2:2]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[0:0]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
1 ^ (x[0:0]) ^ (x[1:1]) ^ (x[0:0]&x[1:1]) ^ (x[3:3]) ^ (x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[3:3]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]) ^ (x[0:0]&x[1:1]&x[4:4]) ^ (x[2:2]&x[4:4]) ^ (x[1:1]&x[2:2]&x[4:4]) ^ (x[0:0]&x[1:1]&x[2:2]&x[4:4]) ^ (x[1:1]&x[3:3]&x[4:4]) ^ (x[0:0]&x[1:1]&x[3:3]&x[4:4]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]) ^ (x[0:0]&x[5:5]) ^ (x[1:1]&x[5:5]) ^ (x[2:2]&x[5:5]) ^ (x[1:1]&x[2:2]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[5:5]) ^ (x[3:3]&x[5:5]) ^ (x[1:1]&x[3:3]&x[5:5]) ^ (x[2:2]&x[3:3]&x[5:5]) ^ (x[0:0]&x[1:1]&x[2:2]&x[3:3]&x[5:5]) ^ (x[4:4]&x[5:5]) ^ (x[1:1]&x[4:4]&x[5:5]) ^ (x[0:0]&x[1:1]&x[4:4]&x[5:5]) ^ (x[2:2]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[4:4]&x[5:5]) ^ (x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[3:3]&x[4:4]&x[5:5]) ^ (x[2:2]&x[3:3]&x[4:4]&x[5:5]) ^ (x[1:1]&x[2:2]&x[3:3]&x[4:4]&x[5:5])
"""
