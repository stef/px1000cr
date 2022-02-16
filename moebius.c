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

void moebius(uint8_t *S, int n) {
   int i, j, Sz, Pos;
   for(i=0;i<n;i++) {
     for(Pos=0,Sz=1<<i; Pos < (1<<n); Pos += 2*Sz) {
         for(j=0;j<Sz-1;j++) {
            S[Pos+Sz+j]=S[Pos+j] ^ S[Pos + Sz +j];
         }
      }
   }
}

// bugged, indexes way outside of A
//void moebius2(uint8_t *A, int n) {
//   int i,k,l;
//   for(i=1;i<=n;i++) {
//      for(k=0;k<(1<<(n-i));k++) {
//         for(l=0;l<(1<<(i-1));l++) {
//           printf("%d ", k*(1<<i)+l+(1<<i));
//           A[k*(1<<i)+l+(1<<i)]^=A[k*(1<<i)+l];
//         }
//      }
//   }
//}

// src sci-gems.math.bas.bg/jspui/bitstream/10525/2935/1/sjc-vol11-num1-2017-p045-p057.pdf
void moebius2(uint8_t *f, int n) {
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
  uint8_t f[8][64]={0}, f2[8][64]={0};
  for(i=0;i<8;i++) {
    // initialize f
    for(j=0;j<64;j++) {
      f[i][j]=(lookupTable6To1bit[j] >> i) & 1;
      f2[i][j]=f[i][j];
    }
    ones=0;
    for(j=0;j<64;j++) {
      ones+=f[i][j];
      printf("%d",f[i][j]);
    }
    printf(" %d \n", ones);

    //moebius(f[i],6);
    //ones=0;
    //for(j=0;j<64;j++) {
    //  ones+=f[i][j];
    //  printf("%d",f[i][j]);
    //}
    //printf(" %d \n", ones);

    moebius2(f2[i],6);
    ones=0;
    for(j=0;j<64;j++) {
      ones+=f2[i][j];
      printf("%d",f2[i][j]);
    }
    printf(" %d \n\n", ones);
  }
  //printf("matches: %d\n",memcmp(f,f2,8*64));
  return 0;
}
