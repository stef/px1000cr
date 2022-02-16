* Files related to PoC||GTFO 21:21 - NSA’s Backdoor of the PX1000-Cr

64bit2key.py       - tool taking a key, returning possible 16 byte password
PX1000_EPROM.map   - the memory map of the px1000cr
PX1000_EPROM.s19   - the px1000cr ROM in s19 format - for the simulator
PX1000_EPROM.sim   - startup script for the simulator
anf.jpg            - the formula for the ANF from A. Joux' tome
angr_tgt.c         - a synthesized LFSR implementation for angr
angr_tgt.py        - angr script to extract constraints for the LFSR
blockschema.svg    - the blockschema made by the Crypto Museum people
core.[ch]          - encryption implementation
decrypt.c          - a decrypt tool based on core.[ch]
docs/              - various docs that contributed to the attack
encrypt.c          - an encrypt tool based on core.[ch]
f-anf.py           - construct, verify and output the ANF of F
lfsr-next-bits.py  - analyze the dependency graph of the LFSR bits
lfsr-next-bits.txt - the LFSR bit dependency graph
lfsr.c             - c implementation of the four LFSRs
lfsr.jpg           - the LFSR diagram
lfsr32.py          - extracting the four LFSRs from the lookupTable
moebius.c          - calculate the Möbius transform of F
moebius4.py        - calculate the Möbius and ANF of the 4-to-4 mapping
px1000.jpg         - an image of the PX1000cr
px1k-claripy.py    - the final attack
px1kcr.c           - the most literal c implementation of the EPROM
readme.md          - this file
utils.[ch]         - various debug and experimental functions
writeup.txt        - the writeup
