#!/usr/bin/env python

import sys

#vk = 0x0810003201337f24
#vk = 0x082ef9c7a3229dcf

vk = int(sys.argv[1],16)

print('\n'.join(
    ''.join(
        [chr(((vk >> (n<<2)) & 0xf) | (b << 4))
         if (((vk >> (n<<2)) & 0xf) | (b << 4)) < 127
         else '_'
         for n
         in reversed(range(16))])
    for b
    in range(2,8)))
