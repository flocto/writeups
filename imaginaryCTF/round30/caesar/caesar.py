#!/usr/bin/env python3

from random import randint

alphabet = bytes(range(32, 127))

caesar = lambda s, key: bytes(alphabet[(c+key+i)%len(alphabet)] for i, c in enumerate(s))

# flag = open("flag.txt", "rb").read()

# print(caesar(flag, randint(0,2**32)))

# Output:
# b'~y,~5/$&1})4!:,>%>-(.::SB.ED727_`T'

enc = b'~y,~5/$&1})4!:,>%>-(.::SB.ED727_`T'
for key in range(0, 127-32):
    dec = lambda s: bytes(alphabet[(c-key-i)%len(alphabet)] for i, c in enumerate(s))
    # print(dec(enc), key)
    if b'ictf{' in dec(enc):
        print(dec(enc), key)
        break
