import random

seed = random.getrandbits(64 * 8)
mask = (1 << 64) - 1
state_1 = random.getrandbits(64)
state_2 = (state_1 + random.getrandbits(64)) & mask

with open("bip39.txt") as f:
    bip = [i for i in f.read().split("\n") if i]

def generate_token():
    global seed, state_1, state_2, mask
    result = seed & mask
    seed >>= 64
    inc = ((result * state_1 + state_2) ^ seed) & mask
    seed |= inc << (7 * 64)
    return result

def convert_to_string(token):
    r = token
    n = []
    for i in range(6):
        n.append(token & 0x7FF)
        token >>= 11
    return "-".join([bip[i] for i in n])

print("Tokens for the next month:")
print("\n".join(["  " + convert_to_string(generate_token()) for i in range(0, 31)]))