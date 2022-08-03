# Wringing Rings
## Description
>Everyone says we should use finite fields, but I loved sharing secrets this way so much that I put a ring on it!
## Attachments
>[server.py](ringring.py)
>
>$ nc ring.chal.uiuc.tf 1337
---

## Secrets
They give source code, so let's look at that first.
```py
import sympy as sp
import random
import signal
from secret import FLAG

secret = random.SystemRandom().randint(1, 500_000)

_MAX = 10 ** (len(str(secret)) - 1)

# generating a polynomial
def _f(secret, minimum=3):
    coeffs = [secret] + [
        random.SystemRandom().randint(1, _MAX) for _ in range(minimum - 1)
    ]

    # print("Secret Polynomial:")
    # f_str = str(secret)
    # for i, coeff in enumerate(coeffs[1:]):
    #     f_str += " + " + str(coeff) + "*x^" + str(i + 1)
    # print(f_str)

    def f(x):
        res = 0
        for i, coeff in enumerate(coeffs):
            res += coeff * x ** (i)

        return res

    return f


def gen_shares(secret, minimum=3):
    f = _f(secret, minimum)
    shares = [(i + 1, f(i + 1)) for i in range(minimum)]
    return shares


def challenge(secret, minimum=3):
    shares = gen_shares(secret, minimum)
    points = random.sample(shares, minimum - 1)
    points.sort()
    return points


def main():
    minimum = 10
    points = challenge(secret, minimum)

    print("[SSSS] Known shares of the secret polynomial: ")
    for point in points:
        print(f"       {point}")
    print()
    
    signal.alarm(60)
    guess = int(input("[SSSS] Enter my secret: "))
    if guess == secret:
        print(f"[SSSS] Correct! {FLAG}")
    else:
        print("[SSSS] Incorrect...")
    
if __name__ == "__main__":
    main()
```
There's some secret value that's generated from 1 to 500,000 (including both ends). 
```py
secret = random.SystemRandom().randint(1, 500_000)
```
Then, a polynomial of degree 10 is created with integer coefficients between 1 and $10^{\lfloor\log_{10}{secret}\rfloor}$. The constant
of the polynomial is also set to the secret.
```py
minimum = 10
points = challenge(secret, minimum)


_MAX = 10 ** (len(str(secret)) - 1)
def _f(secret, minimum=3):
    coeffs = [secret] + [
        random.SystemRandom().randint(1, _MAX) for _ in range(minimum - 1) # minimum is 10, so 9 coefs are generated
    ]

    # print("Secret Polynomial:")
    # f_str = str(secret)
    # for i, coeff in enumerate(coeffs[1:]):
    #     f_str += " + " + str(coeff) + "*x^" + str(i + 1)
    # print(f_str)

    def f(x):
        res = 0
        for i, coeff in enumerate(coeffs):
            res += coeff * x ** (i)

        return res
    return f
```
And finally, 9 points from the polynomial are printed.
```py
def gen_shares(secret, minimum=3):
    f = _f(secret, minimum)
    shares = [(i + 1, f(i + 1)) for i in range(minimum)]
    return shares


def challenge(secret, minimum=3):
    shares = gen_shares(secret, minimum)
    points = random.sample(shares, minimum - 1) # 10 - 1 = 9 points are sampled
    points.sort()
    return points
###
print("[SSSS] Known shares of the secret polynomial: ")
for point in points:
    print(f"       {point}")
print()
```
Finally the server asks for the secret, giving the flag if correct.
```py
guess = int(input("[SSSS] Enter my secret: "))
if guess == secret:
    print(f"[SSSS] Correct! {FLAG}")
else:
    print("[SSSS] Incorrect...")
```

## Polynomial interpolation
Doing some [research online](https://en.wikipedia.org/wiki/Polynomial_interpolation#Interpolation_theorem) (or paying attention to algebra), 
we know that given $n + 1$ points, there always exists a unique polynomial of (at most) degree $n$ that passes through all the points.

In Python, we can use `scipy.interpolate.lagrange` to get the Lagrange polynomial that approximates the interpolation. Just
pass it the x and y values of the points and it will return an approximate polynomial. Additionaly, the secret polynomial generated only has integer
coefficients, meaning that we can parse the returned polynomial's coefficients to check if they are close to integers.

However, there's still a problem. To get the full polynomial of degree 9, there needs to be 10 points. However, the server only prints
out 9 points. This means a point is still missing.

## Not a ring
Let's consider the point at $x = 0$. On that point, the y evaluated from the polynomial would be equal to the secret, as none of the 
$x$ terms in the polynomial actually matter. Additionally, the range of the secret is only from 1 to 500,000, meaning all possible
values can be tested by just creating a point at $(0, y)$ and adding that point to the already existing points.
```python
from scipy.interpolate import lagrange
for i in range(1, 500000):
    graph = [(0, i)] + pts
    x = np.array([p[0] for p in graph])
    y = np.array([p[1] for p in graph])
    poly = lagrange(x, y) 
    coefs = poly.coefs
    # close to integer coefficients work
```
As long as all the coefficients are somewhat close to integers (within 0.001), the `i` value can be assumed to be the secret. This is because for a polynomial
of degree 10, its very *very* unlikely that in the range of possible secret values, more than 1 polynomial will have ALL close to integer coefficients.

## Solve
This was my final solve script:
```python
from scipy.interpolate import lagrange
import numpy as np
from numpy.polynomial.polynomial import Polynomial

def solve(pts):
    secrets = []
    from tqdm import tqdm # only takes ~20 minutes for all values
    for i in tqdm(range(1, 500001)):
        graph = [(0, i)] + pts
        x = np.array([p[0] for p in graph])
        y = np.array([p[1] for p in graph])
        poly = lagrange(x, y)
        coefs = poly.coef
        valid = True
        for coef in coefs:
            if coef < 0:
                valid = False
                break
            coefint = round(coef)
            if abs(coefint - coef) > 0.01:
                valid = False
                break
            if coefint > i:
                valid = False
                break
        if valid:
            secrets.append(i)
            print()
            print(i)
            print()
            break
    return secrets

import pwn
#nc ring.chal.uiuc.tf 1337
s = pwn.remote('ring.chal.uiuc.tf', 1337)
print(s.recvline())
print(s.recvline())
pts = []
for i in range(9):
    line = s.recvline().decode('utf-8').strip()
    print(line)
    pt = eval(line)
    pts.append(pt)
print(pts)
secrets = solve(pts)
print(secrets)
s.sendline(str(secrets[0]).encode())
s.interactive()
```
After running, the flag is:
```
uiuctf{turn5_0ut_th4t_th3_1nt3g3r5_4l50_5uck}
```

## Conclusion
Pretty open-ended challenge, main step is figuring out what to do.
After you pinpoint out the objective, there's multiple ways to solve for the coefficients.
I saw one solution using gaussian which was cool. Otherwise somewhat straightforward as long as you are
able to come up with a way to get the coefficients.