#!/usr/bin/env python

map4to4bit=[
   [0x6, 0xA, 0x1, 0x2, 0xE, 0x7, 0x8, 0x9,
    0xC, 0x4, 0x3, 0xF, 0xB, 0x0, 0x5, 0xD],
   [0x2, 0x7, 0x0, 0x5, 0xF, 0x3, 0x1, 0x9,
    0xE, 0xD, 0xB, 0x8, 0xC, 0xA, 0x4, 0x6],
   [0x9, 0x1, 0x3, 0xC, 0x2, 0x0, 0xA, 0xE,
    0xD, 0x6, 0xB, 0x7, 0x5, 0x8, 0xF, 0x4],
   [0xB, 0x6, 0x9, 0x0, 0x5, 0xE, 0xF, 0x8,
    0x4, 0xC, 0x1, 0xD, 0x2, 0x7, 0x3, 0xA]]

# src sci-gems.math.bas.bg/jspui/bitstream/10525/2935/1/sjc-vol11-num1-2017-p045-p057.pdf
def moebius(f,n):
    blocksize=1
    for step in range(1,n+1):
        source=0
        while(source < (1<<n)):
            target = source + blocksize
            for i in range(blocksize):
                f[target+i]^=f[source+i]
            source+=2*blocksize
        blocksize*=2

def test():
    lookupTable6To1bit=[
        0x96, 0x4b, 0x65, 0x3a, 0xac, 0x6c, 0x53, 0x74,
        0x78, 0xa5, 0x47, 0xb2, 0x4d, 0xa6, 0x59, 0x5a,
        0x8d, 0x56, 0x2b, 0xc3, 0x71, 0xd2, 0x66, 0x3c,
        0x1d, 0xc9, 0x93, 0x2e, 0xa9, 0x72, 0x17, 0xb1,
        0xb4, 0xe4, 0xa3, 0x4e, 0x27, 0x5c, 0x8b, 0xc5,
        0xe8, 0x95, 0xe1, 0xd1, 0x87, 0xb8, 0x1e, 0xca,
        0x1b, 0x63, 0xd8, 0x2d, 0xd4, 0x9a, 0x99, 0x36,
        0x8e, 0xc6, 0x69, 0xe2, 0x39, 0x35, 0x6a, 0x9c
    ]

    f=[[0]*64,[0]*64,[0]*64,[0]*64,[0]*64,[0]*64,[0]*64,[0]*64]
    for i in range(8):
        ones=0
        for j in range(64):
            f[i][j]=(lookupTable6To1bit[j] >> i) & 1
            ones+=f[i][j]
            print(f[i][j], end='')
        print("", ones)

        moebius(f[i],6)
        ones=0
        for j in range(64):
            ones+=f[i][j]
            print(f[i][j], end='')
        print('', ones)
        print()

fs=[[[0]*16,[0]*16,[0]*16,[0]*16],[[0]*16,[0]*16,[0]*16,[0]*16],[[0]*16,[0]*16,[0]*16,[0]*16],[[0]*16,[0]*16,[0]*16,[0]*16]]
ms=[[[0]*16,[0]*16,[0]*16,[0]*16],[[0]*16,[0]*16,[0]*16,[0]*16],[[0]*16,[0]*16,[0]*16,[0]*16],[[0]*16,[0]*16,[0]*16,[0]*16]]
for p in range(4):
    print("position", p)
    for bit in range(4):
        print("bit", bit)
        ones=0
        for i in range(16):
            fs[p][bit][i]=(map4to4bit[p][i] >> bit) & 1
            ms[p][bit][i]=fs[p][bit][i]
            ones+=fs[p][bit][i]
        print(''.join(f"{b}" for b in fs[p][bit]), ones)
        moebius(ms[p][bit],4)
        print(''.join(f"{b}" for b in ms[p][bit]), ms[p][bit].count(1))
        print()

for p in range(4):
    for j, (f, m) in enumerate(zip(fs[p],ms[p])):
        f_ = ' ^ '.join(c for c in ['&'.join(f"x{i}" for i, x in enumerate(reversed(f'{a:04b}')) if x =='1') for a in range(16) if m[a]==1] if c)
        if (p,j) in [(0,1),(0,2), (1,1), (2,0), (2,3), (3,0), (3,1), (3,3)]: # they have odd number of 1 constant terms in their polinomial
            f_ = '1 ^ ' + f_
        print((p,j), f_)
        evaled =''.join(str(eval(f_, {f"x{i}":int(x) for i, x in enumerate(reversed(f'{a:04b}'))})) for a in range(16))
        #print(''.join(f"{b}" for b in f))
        #print(evaled)
        assert evaled==''.join(f"{b}" for b in f)

    f_ = []
    for j, (f, m) in enumerate(zip(fs[p],ms[p])):
        f_.append(' ^ '.join('('+c+')' for c in ['&'.join(f"x[{i}]" for i, x in enumerate(reversed(f'{a:04b}')) if x =='1') for a in range(16) if m[a]==1] if c))
        if (p,j) in [(0,1),(0,2), (1,1), (2,0), (2,3), (3,0), (3,1), (3,3)]: # they have odd number of 1 constant terms in their polinomial
            f_[-1] = '1 ^ ' + f_[-1]
    print(', '.join(reversed(f_)))


"""
import claripy

x = claripy.BVS('x', 8)

y0 = x[1] ^ x[0]&x[1] ^ x[0]&x[2] ^ x[1]&x[2] ^ x[0]&x[1]&x[2] ^ x[0]&x[1]&x[3] ^ x[2]&x[3]

s = claripy.Solver()

''.join(str(r[0]) for r in [s.eval(y0, 1, extra_constraints=[x==i]) for i in range(16)])

'0010010100111011'
"""
