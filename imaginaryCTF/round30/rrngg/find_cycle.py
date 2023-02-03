#!/usr/bin/env python3
import random
from Crypto.Util.number import long_to_bytes as ltb
from Crypto.Util.strxor import strxor

total = 1

# getPrime(512) from Crypto.Util.number
prime = 9748729228494339631846388699994098788507701354484040512690379598196693697693937149457269291065421274894121574705508351692344913516332264306279955933193803

seed_set = set()
random.seed(0)

for i in range(10**5):
    r = random.getrandbits(24)
    total *= r
    total %= prime 
    random.seed(r)
    if r in seed_set:
        print(i, r)
        seed_set.clear()
        seed_set.add(r)
    seed_set.add(r)