#!/usr/bin/env python

# requires a cleaned output of angr_tgt.py for the lfsr function
# split up that output into one line per bit, and for that bit only
# keep the indexes of the bits that contribute to this particular bit
# in the previous state.

with open('lfsr-next-bits.txt','r') as f:
    bits = [list(sorted(int(idx) for idx in line.split() if idx)) for line in reversed(f.readlines())]

print('\n'.join(str(x) for x in bits))

def walk(bit, c):
    c.append(bit)
    for b in bits[bit]:
        if b in c: continue
        c=walk(b,c)
    return c

from PIL import Image, ImageDraw, ImageFont
#im = Image.new('RGB', (16*9, 8*9), (255, 255, 255))
im = Image.new('RGB', (1216, 608), (255, 255, 255)) # 1216 = 76 * 16, 608 = 76 * 8
fnt = ImageFont.truetype("/usr/share/fonts/truetype/msttcorefonts/Andale_Mono.ttf", 25)
draw = ImageDraw.Draw(im)
colors = {0: (255,0,0), 2: (0,255,0), 4: (0,0,255), 6: (0,255,255)}
secondary= {95: (0,0,255), 103: (0,0,255), 111: (0,0,255), 119: (0,0,255), 127: (0,0,255), 109: (0,255,0), 117: (0,255,0), 125: (0,255,0), 123: (255,0,0)}
fill={15: (255,255,0), 15-7: (255,255,0)}

seen=set()
drawn=set()
for bit in range(128):
    b = tuple(sorted(walk(bit,[])))
    if b in seen: continue
    seen.add(b)
    for p in b:
        if p in drawn: continue
        draw.rectangle((((127-p)//8)*76, (p%8) * 76, ((127-p)//8)*76 + 75, (p%8) * 76 + 75), fill=colors.get(bit, (255,255,0)), outline=fill.get(p//8, (0, 0, 0)))
        if secondary.get(bit):
            draw.polygon([(((127-p)//8)*76, (p%8) * 76), (((127-p)//8)*76, (p%8) * 76 + 75), (((127-p)//8)*76 + 75, (p%8) * 76 + 75)], fill=secondary[bit], outline=fill.get(p//8, (0, 0, 0)))
        draw.text((((127-p)//8)*76+38, (p%8) * 76 + 38), str(p), anchor="mm", font=fnt, fill=(255,255,255), stroke_fill=(0,0,0), stroke_width=1)
        drawn.add(p)
    print(bit, len(b), b)

im.save('lfsr.png')

# outputs
"""
0 32 (0, 1, 8, 9, 16, 17, 24, 25, 32, 33, 40, 41, 48, 49, 56, 57, 64, 65, 72, 73, 80, 81, 88, 89, 96, 97, 104, 105, 112, 113, 120, 121)
2 31 (2, 3, 10, 11, 18, 19, 26, 27, 34, 35, 42, 43, 50, 51, 58, 59, 66, 67, 74, 75, 82, 83, 90, 91, 98, 99, 106, 107, 114, 115, 122)
4 29 (4, 5, 12, 13, 20, 21, 28, 29, 36, 37, 44, 45, 52, 53, 60, 61, 68, 69, 76, 77, 84, 85, 92, 93, 100, 101, 108, 116, 124)
6 27 (6, 7, 14, 15, 22, 23, 30, 31, 38, 39, 46, 47, 54, 55, 62, 63, 70, 71, 78, 79, 86, 87, 94, 102, 110, 118, 126)

95 28  (6, 7, 14, 15, 22, 23, 30, 31, 38, 39, 46, 47, 54, 55, 62, 63, 70, 71, 78, 79, 86, 87, 94, 95, 102, 110, 118, 126)
103 28 (6, 7, 14, 15, 22, 23, 30, 31, 38, 39, 46, 47, 54, 55, 62, 63, 70, 71, 78, 79, 86, 87, 94, 102, 103, 110, 118, 126)
109 30 (4, 5, 12, 13, 20, 21, 28, 29, 36, 37, 44, 45, 52, 53, 60, 61, 68, 69, 76, 77, 84, 85, 92, 93, 100, 101, 108, 109, 116, 124)
111 28 (6, 7, 14, 15, 22, 23, 30, 31, 38, 39, 46, 47, 54, 55, 62, 63, 70, 71, 78, 79, 86, 87, 94, 102, 110, 111, 118, 126)
117 30 (4, 5, 12, 13, 20, 21, 28, 29, 36, 37, 44, 45, 52, 53, 60, 61, 68, 69, 76, 77, 84, 85, 92, 93, 100, 101, 108, 116, 117, 124)
119 28 (6, 7, 14, 15, 22, 23, 30, 31, 38, 39, 46, 47, 54, 55, 62, 63, 70, 71, 78, 79, 86, 87, 94, 102, 110, 118, 119, 126)
123 32 (2, 3, 10, 11, 18, 19, 26, 27, 34, 35, 42, 43, 50, 51, 58, 59, 66, 67, 74, 75, 82, 83, 90, 91, 98, 99, 106, 107, 114, 115, 122, 123)
125 30 (4, 5, 12, 13, 20, 21, 28, 29, 36, 37, 44, 45, 52, 53, 60, 61, 68, 69, 76, 77, 84, 85, 92, 93, 100, 101, 108, 116, 124, 125)
127 28 (6, 7, 14, 15, 22, 23, 30, 31, 38, 39, 46, 47, 54, 55, 62, 63, 70, 71, 78, 79, 86, 87, 94, 102, 110, 118, 126, 127)
"""
