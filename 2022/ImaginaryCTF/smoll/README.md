# smoll
## Description
>Just a regular, run-of-the-mill RSA challenge, right? Right?
## Attachments
>[smoll.py](smoll.py) [output.txt](output.txt)
---

# Standard RSA?
**!Warning, math ahead!**<br/>
Looking at the script, we see what appears to just be some normal RSA code. 
```python
from secret import p, q
from sage.all import factor

for r in [p, q]:
    for s, _ in factor(r - 1):
        assert int(s).bit_length() <= 20

n = p * q
e = 0x10001

with open("flag.txt", "rb") as f:
    flag = int.from_bytes(f.read().strip(), "big")
assert flag < n

ct = pow(flag, e, n)
print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")
```
## RSA explanation
[RSA, or Rivest-Shamir-Adleman](https://en.wikipedia.org/wiki/RSA_(cryptosystem)), is a public key asymmetric cryptosystem.
 
It starts by first generating two large prime numbers $p$ and $q$. These primes are what create the entire system. <br/>
Then, a modulo $n$ is defined as $p \cdot q$. With $n$, a value $\phi$ is also calculated. $\phi$ is usually defined as $\phi(n)$, or the Euler totient function.
However, Carmichael's totient function also works. Because $n$ is the product of $p$ and $q$, two primes, the value of $\phi(n)$ is equal to $(p - 1) \cdot (q - 1)$,
which is how it is commonly represented in code. <br/>
A public exponent $e$ is also defined as any number that is coprime to $\phi$, usually being a prime. 
In this case, $e$ is defined as `0x10001` or `65537`. Together, $(n, e)$ make up the public key. <br/>

For the private key $d$, we take the [modular multiplicative inverse](https://en.wikipedia.org/wiki/Modular_multiplicative_inverse) of $e$ modulo $\phi$. <br />
In Python, we can easily do this with `pow(e, -1, ϕ)`. 

To encrypt a message $m$, we raise $m$ to $e$ modulo $n$. Basically, $c = m ^ e \mod n$. In code, we often convert $m$ into bytes, then convert those bytes into one huge integer
that gets fed into the power.

Finally, to decrypt a message $c$, we raise $c$ to $d$ modulo $n$. This reverse the encryption, essentially computing $m = c ^ d \mod n$. 

### Proof
[Read wikipedia page :yum:](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Proof_using_Fermat's_little_theorem)

## Flag?
To get the flag, it seems we have to somehow find a way to recover the private key. The easiest way to do this would be to find the two primes that make up $n$. Calculating
the totient value is extremely expensive, not to mention $n$ is around 300 digits or so. However, looking at the implementation, there seems to only be a single part
that stands out.
# Factoring
```python
for r in [p, q]:
    for s, _ in factor(r - 1):
        assert int(s).bit_length() <= 20
```
But what does this piece of code do? 

First, we iterate over both $p$ and $q$, then we iterate over each prime factor in $p - 1$ and $q - 1$. <br/>
For each prime factor, we check that it has a bit length less than or equal to 20.
Essentially, we are checking that it has a value less than $2 ^ {21}$, which would require 21 bits. <br/>
Overall, it just means $p - 1$ and $q - 1$ must have prime factors that are below $2 ^ {21} = 2097152$

But how does this help us factor $n$?

Introducing... 
## Pollard's P - 1
Pollard's p - 1 algorithm is a factoring algorithm specifically designed for numbers whose factors are 1 more than a [**powersmooth** number.](https://en.wikipedia.org/wiki/Smooth_number#Powersmooth_numbers)

A n-smooth number is a number whose prime factors are all less than or equal to $n$. For example, $2 \cdot 3 \cdot 5 = 60$ would be considered 5-smooth. <br/>
However, a B-powersmooth number is a number whose **prime powers** are all less than or equal to B.  
$720$ $(2^4 \cdot 3^2 \cdot 5^1)$ would be considered 5-smooth but **NOT** 5-powersmooth. That's because there are prime powers like $2^4 = 16$, $3^2 = 9$, and $2 ^ 3 = 8$ 
that are all above 5. However, it would be considered 16-powersmooth because no prime power $p^k$ that factors $720$ is greater than $16$.

Pollard's p - 1 algorithm is defined as such:
1. Select the smoothness bound $B$
2. Define $M = \prod\limits_{\text{primes } p \le B}{q ^ {\lfloor\log_{q}{B}\rfloor}}$
3. Randomly pick $a$ such that it is coprime to $n$, $2$ works because $n$ is odd for RSA.
4. Compute $g = gcd(a^M - 1, n)$
5. If $g = 1$, try again with a bigger $B$
6. If $g = n$, try again with a smaller $B$.
7. Otherwise you can return $g$ knowing you have found a prime factor of $n$.
   
You can find an example and a more detailed explanation [here.](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm#Example)

Let's try implementing this for our problem. We'll substitute the product with a factorial to hopefully have a higher chance of finding a factor.
(This is because a factorial will increase the power of the primes we check, giving a higher chance of finding a factor)
```python
# partially stolen from https://ctftime.org/writeup/32914
from gmpy2 import fac
from math import gcd
from Crypto.Util.number import *

n = 13499674168194561466922316170242276798504319181439855249990301432638272860625833163910240845751072537454409673251895471438416265237739552031051231793428184850123919306354002012853393046964765903473183152496753902632017353507140401241943223024609065186313736615344552390240803401818454235028841174032276853980750514304794215328089
c = 12788784649128212003443801911238808677531529190358823987334139319133754409389076097878414688640165839022887582926546173865855012998136944892452542475239921395969959310532820340139252675765294080402729272319702232876148895288145134547288146650876233255475567026292174825779608187676620580631055656699361300542021447857973327523254

a = 2
# 20 bits of length
B = 2 ** 21
   
gcd_value = 1
while True:
    # print(B)
    b = fac(B)
    
    tmp1 = n
    tmp2 = pow(a, b, n) - 1
    gcd_value = gcd(tmp1, tmp2)

    print("n" if gcd_value == n else gcd_value)
    if gcd_value == 1:
        B += 1
    elif gcd_value == n:
        B -= 1
    else:
        break
#gcd_value now contains a prime factor
```
Running the algorithm, we see it takes way too long. 
I left it running for at least 30 minutes with nothing substantial... Maybe we could improve the speed somehow?

## I love binary search
Given that we increase B when gcd is 1 and decrease it otherwise, we can see that at some point, there must be a number that causes a transition from 1 to n.
This critical point should be where gcd will be equal to a factor of $n$. (There is an exception, but I will explain it later)

Then, using binary search, we should be able to drastically speed up our program. I defined the right pointer as $2^{22}$ because we know the initial bound was $2^{21}$ from earlier, so I wanted something just an order of magnitude higher. The left pointer was defined as $2^{20}$ just because I didn't really think it would end up below that value, but defining it
at 0 is probably the safest.
```python
# partially stolen from https://ctftime.org/writeup/32914
from gmpy2 import fac
from math import gcd
from Crypto.Util.number import *

n = 13499674168194561466922316170242276798504319181439855249990301432638272860625833163910240845751072537454409673251895471438416265237739552031051231793428184850123919306354002012853393046964765903473183152496753902632017353507140401241943223024609065186313736615344552390240803401818454235028841174032276853980750514304794215328089
c = 12788784649128212003443801911238808677531529190358823987334139319133754409389076097878414688640165839022887582926546173865855012998136944892452542475239921395969959310532820340139252675765294080402729272319702232876148895288145134547288146650876233255475567026292174825779608187676620580631055656699361300542021447857973327523254

a = 2
# 20 bits of length
l = 2 ** 20
r = 2 ** 22
B = (l + r) // 2
   
gcd_value = 1
while True:
    B = (l + r) // 2
    print(B, l, r)
    b = fac(B)
    
    tmp1 = n
    tmp2 = pow(a, b, n) - 1
    gcd_value = gcd(tmp1, tmp2)

    print("n" if gcd_value == n else gcd_value)
    if gcd_value == 1:
        l = B
    elif gcd_value == n:
        r = B
    else:
        break

p = gcd_value
q = n // p
e = 0x10001

print(f"[+] p factor : {p}")
print(f"[+] q factor : {q}")

phi = (p-1)*(q-1)
d = inverse(e, phi)

m = pow(c, d, n)

flag = long_to_bytes(m)

print(flag)
```
If we run this, we actually get the flag in a few iterations!
```
>>> b'ictf{wh4t_1f_w3_sh4r3d_0ur_l4rge$t_fact0r_jk_unl3ss??}'
```

## Note
As it turns out, this is an unintended solution. However, there was an even bigger unintended solution, which was that $n$ was leaked on factordb...

Anyway, the reason this solution is unintended is because $p - 1$ and $q - 1$ actually share their largest prime factors. This means that when we try to 
run Pollard's p - 1 regularly, we end up actually skipping directly from 1 to $n$ when calculating the gcd. The problem is that using the bounds we ran 
on the binary search, we up getting lucky and getting a $B$ such that $B!$ is a multiple of $p - 1$ but not $q - 1$. 

Given that this problem had a ton of issues, the organizers of Imaginary CTF released `lorge`, an almost identical problem, just with slightly larger bounds
and fixed leaks (ie. not on factordb :facepalm:). On `lorge`, you also have to use a modified pollard p - 1 due to the shared factor. <br />
I chose to do a writeup on this problem because I wanted to explore normal pollard p - 1 combined with
binary search. In fact, binary search isn't even guaranteed to work every time because the exponents are all done modulo n (?)

<sub> (Actually I'm not even 100% sure, I suck at math but I'm reasonably confident binary search won't work or else everyone else would've already used it in their
implementations) </sub>

## Conclusion
This problem would've been a good introduction to pollard p - 1 with shared factors if it didn't get completely destroyed :sob:. Still had fun implementing 
a binary search amalgamated with pollard p - 1 though.