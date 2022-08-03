from scipy.interpolate import lagrange
import numpy as np
from numpy.polynomial.polynomial import Polynomial

def solve(pts):
    secrets = []
    from tqdm import tqdm
    for i in tqdm(range(1, 500000)):
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