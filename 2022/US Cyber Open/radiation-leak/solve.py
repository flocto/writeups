indexes = {} 
with open("bip39.txt") as f:
    bip = [i for i in f.read().split("\n") if i]

def convert_to_string(token):
    r = token
    n = []
    for i in range(6):
        n.append(token & 0x7FF)
        token >>= 11
    return "-".join([bip[i] for i in n])

for i in range(len(bip)):
    indexes[bip[i]] = i

with open("last.txt", "r") as f:
    last = f.read().splitlines()

nums = []
for line in last:
    words = line.split("-")
    res = 0
    for i, word in enumerate(words):
        res |= indexes[word] << (11 * i)
    
    nums.append(res)

print(nums)
from z3 import Solver, BitVec
s = Solver()
state1 = BitVec("state1", 64)
state2 = BitVec("state2", 64)
mask = (1 << 64) - 1 # limit to 64 bits
for i in range(len(nums) - 8):
    result: int = nums[i]
    seed2: int = nums[i + 1]
    next: int = nums[i + 8]
    s.add(next == ((result * state1 + state2) ^ seed2) & mask)
s.check()
res = s.model()
print(res)
state1 = 336801044331229251 
state2 = 10569036738506978277
mask = (1 << 64) - 1 

for i in range(len(nums) - 8):
    result: int = nums[i]
    seed2: int = nums[i + 1]
    next: int = nums[i + 8]
    assert(next == ((result * state1 + state2) ^ seed2) & mask)

# make next seed segment
token = nums[len(nums) - 8]
seed2 = nums[len(nums) - 7]
next = ((token * state1 + state2) ^ seed2) & mask
print(next)
print(convert_to_string(next))