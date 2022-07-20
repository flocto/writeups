# Radiation
>For the past month, your keylogger has been successfully stealing the passcodes for this admin portal (https://metaproblems.com/6f5fa97da7de2648c1531316ebe26954/portal/) for a shady mining company, but they've finally managed to remove your access. They change the code daily. Can you figure out a way to log in now?
>
>Here are the codes (https://metaproblems.com/6f5fa97da7de2648c1531316ebe26954/leaked_tokens.txt) for the previous 30 days and the script they use to generate them (https://metaproblems.com/6f5fa97da7de2648c1531316ebe26954/token_generator.py)

# Introduction
We're given 3 sites here. The first is a simple login portal with a password and captcha, the second is a list of some passwords, and the last is
the python script used to generate the passwords.
![Login portal](portal.png)
```
friend-border-cinnamon-laundry-shoot-chronic
fatigue-photo-result-season-spawn-common
van-service-similar-glory-east-brave
author-sibling-predict-theory-uphold-chuckle
budget-cradle-fatigue-dumb-verb-canvas
gas-token-salute-only-olympic-disorder
...(30 passwords total)
```
```python
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
```
The goal of this challenge seems to be finding the next password given the past 30 passwords, and logging into the portal to claim the flag.

## Password generation
First, let's take a look at the script to see how the passwords are generated.
```python
import random

seed = random.getrandbits(64 * 8)
mask = (1 << 64) - 1
state_1 = random.getrandbits(64)
state_2 = (state_1 + random.getrandbits(64)) & mask
```
The script starts by initializing a seed that is 8 chunks of 64 bits, a mask that is 64 1 bits, and 2 random state values.
```
with open("bip39.txt") as f:
    bip = [i for i in f.read().split("\n") if i]
```
Then it reads from some file called `bip39.txt`. Doing some researching online, I found that it was most likely referring to the [BIP 39 word list](https://privacypros.io/bip39-word-list/) used to generate recovery phrases for Bitcoin wallets. The words are all chosen specifically to have their first 4 letters be unique.
I ended up copying the list from a [source online.](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt)
```python
def generate_token():
    global seed, state_1, state_2, mask
    result = seed & mask
    seed >>= 64
    inc = ((result * state_1 + state_2) ^ seed) & mask
    seed |= inc << (7 * 64)
    return result
```
Next, the script defines a function `generate_token()`. The function uses the seed, states, and mask initialized earlier.

It starts by taking the result of a binary `and` between seed and mask. This is essentially the same as taking the last 64 bits of seed, as mask is just 64 1 bits, so 
any 1 bit in seed that is in the last 64 bits will remain in result, while the 0 bits will stay 0. This means result is at most also 64 bits.

Then, the function bit shifts seed 64 bits to the left. This removes the part that was just `and`ed with mask, essentially just removing the last 64 bits of seed and putting
them in result.

Then, the function does some calculation with result, the 2 states, seed, finally `and`ing the result with mask. This produces a value that is at most 64 bits, like result.
This also means what when `(result * state_1 + state_2)` is xored with seed, only the last 64 bits matter, as the rest of the bits are all removed by the `and` with mask.

This final value is `|`'d, or bitwise `or`ed with seed after being shifted 7 * 64 bits. However, because seed was bitshifted left 64 bits earlier, those 64 bits at its very front
are now all 0. This means the new value is basically just prepended to seed.

Finally, `result` from earlier is returned.

From this function, we can see that seed essentially acts like a buffer containing 8 segments, each segment being 64 bits each. When the `generate_token()` function is called,
the first value in seed is returned, a new value is calculated from the first and second values in seed (as well as the state constants), and that value is added to the last position in seed.

```python
def convert_to_string(token):
    r = token
    n = []
    for i in range(6):
        n.append(token & 0x7FF)
        token >>= 11
    return "-".join([bip[i] for i in n])
```
Finally, this function takes in a token, and seems to generate 6 different words. From the list of passwords we have, we can see that each one is 6 words, all from
the bip39 wordlist, and all with hyphens between. This function seems to just convert the token created in `generate_token` to an actual password.

The function takes the token, `and`s it with `0x7FF`, which is 2047, and shifts token 11 bits. This happens 6 times in total, to generate the 6 words.
This means that from the given passwords, we can find their respective tokens. We already know what the index of each word is
as we have access to the bip39 list, so just by working backwards, we can find their respective tokens.
```python
nums = []
for line in last:
    words = line.split("-")
    res = 0
    for i, word in enumerate(words):
        res |= indexes[word] << (11 * i)
    
    nums.append(res)
# [11665246462824313575, 13396058398880492190, 7864083442092281737, 11706946725526759547, 9725879906172958956, ...]
```
Now that we have their tokens, it seems we just need to reverse engineer the `generate_token` function to find the two state constants, generate
the next token, and find the next password.

# Praise Z3
We should have a lot of space to work with, given that we have 30 passwords. Because the first 8 passwords were already in seed when it was initialized,
we have 22 different equations we can use to find the state values. Instead of doing this by hand or brute forcing though, let's employ Z3:smile:.

[Z3](https://github.com/Z3Prover/z3) is an amazing theorem prover. However, we will be using it here to solve some equations (and hard carry the solve).

The only thing to watch out for is that we will have to initialize the z3 values as `BitVec`s, as those support the `xor` operation used in generating
the next part of seed.
```python
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
```
After just a bit of number crunching, we get our state values!
```
[state1 = 336801044331229251, state2 = 10569036738506978277]
```
From here, all we have to do is the generate the next token, then use that to generate the next password, and log in!
```python
state1 = 336801044331229251
state2 = 10569036738506978277
mask = (1 << 64) - 1 
token = nums[len(nums) - 8]
seed2 = nums[len(nums) - 7]
next = ((token * state1 + state2) ^ seed2) & mask
print(next)
print(convert_to_string(next))
```
And we get our password: `tool-unveil-ranch-soldier-coast-cover`.

Logging into the site, we are greeted with our flag :sunglasses:

![Flag: flag{shouldnt_have_used_my_own_number_generator}](flag.png)
```
flag{shouldnt_have_used_my_own_number_generator}
```
## Full solve script
```python
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
```

---
## Conclusions
Overall it was a really fun and satisfying challenge. Really like how real-world it feels, but you usually get that feeling with a lot of
MetaCTF challenges, so shout-outs to them. Looking forward to see what they'll do for this years MetaCTF.
