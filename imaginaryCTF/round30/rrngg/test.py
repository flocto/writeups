import random
from Crypto.Util.number import long_to_bytes as ltb
from Crypto.Util.strxor import strxor

with open("flag.enc", "rb") as f:
    flag = f.read()

prime = 9748729228494339631846388699994098788507701354484040512690379598196693697693937149457269291065421274894121574705508351692344913516332264306279955933193803

total = 1
random.seed(0)

# starting at 4582, loops every 2153
START = 4582
PERIOD = 2153

for i in range(START):
    r = random.getrandbits(24)
    total *= r
    total %= prime
    random.seed(r)

periodic_total = 1
for i in range(PERIOD):
    r = random.getrandbits(24)
    periodic_total *= r
    periodic_total %= prime
    random.seed(r)

MAX = 10**100
MAX -= START
loops, left = divmod(MAX, PERIOD)

total *= pow(periodic_total, loops, prime)
total %= prime

for i in range(left):
    r = random.getrandbits(24)
    total *= r
    total %= prime
    random.seed(r)

print(total.bit_length())
random.seed(random.getrandbits(24)*total)
print(strxor(flag, ltb(random.getrandbits(len(flag)*8))))