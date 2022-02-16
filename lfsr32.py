#!/usr/bin/env python3

from binascii import unhexlify, hexlify
from itertools import zip_longest

taps_t = (
   0x06, 0x0B, 0x0A, 0x78, 0x0C, 0xE0, 0x29, 0x7B,
   0xCF, 0xC3, 0x4B, 0x2B, 0xCC, 0x82, 0x60, 0x80)

lfsr0=unhexlify("f078d21e0f693c875ac3d2d2692d3cff")
# calculated by running one iteration of the lfsr update loop on lfsr0 - see lfsr.c
lfsr1=unhexlify("dc5bf4e8330fe0807497b02eb71085b0")

def extract(lfsr, i):
    # left to right
    tr = [''.join(str((lfsr[j] >> b) & 1) for j in range(16)) for b in range(8)]
    # horizontal bottoms-up lines appended
    return (tr[(i*2)+1]+tr[(i*2)])

sl = (extract(lfsr0,0),extract(lfsr1,0))

# for testing
print("\nt(lfsr0,0,32)", sl[0])
for b in range(8):
    if(b%4==0): print("\n"+''.join("{:x}".format((lfsr0[i] >> b) & 15) for i in range(16)))
    print(''.join(str((lfsr0[i] >> b) & 1) for i in range(16)))

print("t(lfsr1,0,32)", sl[1])
for b in range(8):
    if(b%4==0): print("\n"+''.join("{:x}".format((lfsr1[i] >> b) & 15) for i in range(16)))
    print(''.join(str((lfsr1[i] >> b) & 1) for i in range(16)))

print('\n'+hexlify(lfsr0).decode('utf8'))

print(sl[0], f"{int(sl[0],2):04x}", sl[1], f"{int(sl[1],2):04x}")

print("\ntaps")
print('\n'+hexlify(bytes(taps_t)).decode('utf8'))
for b in range(8):
    if(b%4==0): print("\n"+''.join("{:x}".format((taps_t[i] >> b) & 15) for i in range(16)))
    print(''.join(str((taps_t[i] >> b) & 1) for i in range(16)))
for k in range(4):
    #taps = ''.join(reversed(extract(taps_t, k)))
    taps = extract(taps_t, k)
    print(taps, f"{int(taps,2):04x}")
