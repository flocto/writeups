import os
os.environ['PWNLIB_NOTERM'] = '1'
from Crypto.Util.number import *
from pwn import remote
from main import Curve, Point
# nc puzzler7.imaginaryctf.org 9003
p = 2**256 - 4294968273
a = 0
b = 7

def dump(G, point, prime, b):
    print('dumping', b)
    gx, gy = G.xy()
    px, py = point
    with open('dump.txt', 'a') as f:
        f.write(f'bs.append({b})\n')
        f.write(f'primes.append({prime})\n')
        f.write(f'dlogs.append((({gx}, {gy}), ({px}, {py})))\n')


def getPoint(x, y):
    r = remote('puzzler7.imaginaryctf.org', int('9003'), level='error')
    r.recvuntil(b'x = ')
    r.sendline(str(x).encode())
    r.recvuntil(b'y = ')
    r.sendline(str(y).encode())
    r.recvuntil(b'x = ')
    x = int(r.recvline().decode())
    r.recvuntil(b'y = ')
    y = int(r.recvline().decode())
    r.close()
    return (x, y)

def getPointDebug(x, y):
    m = int.from_bytes(b'ictf{REDACTED}', 'big')
    E = Curve(p, a, b)
    P = Point(E, x, y)
    Q = m * P
    return Q.x, Q.y

factormap = {
    115792089237316195423570985008687907852598652813156864395638497411212089444244: [
        4, 3, 20412485227, 83380711482738671590122559, 5669387787833452836421905244327672652059
    ],
    115792089237316195423570985008687907853702405052206223696310004874299507848991: [
        9, 169, 3319, 22639, 1013176677300131846900870239606035638738100997248092069256697437031
    ],
    115792089237316195423570985008687907853031073199722524052490918277602762621571: [
        109903, 12977017, 383229727, 211853322379233867315890044223858703031485253961775684523
    ],
    115792089237316195423570985008687907853508896131558604026424249738214906721757: [
        3, 199, 18979, 5128356331187950431517, 1992751017769525324118900703535975744264170999967
    ],
    115792089237316195423570985008687907853941316518124263683276670604605579899084: [
        4, 49, 10903, 5290657, 10833080827, 22921299619447, 41245443549316649091297836755593555342121
    ],
    115792089237316195423570985008687907852837564279074904382605163141518161494337:[
        115792089237316195423570985008687907852837564279074904382605163141518161494337
    ]

}

blacklist = [3]

b = 0
def solveDL():
    global b
    b += 1
    E = EllipticCurve(GF(p), [a, b])
    order = E.order()
    valid = factormap.get(order, None)

    if not valid:
        # print('bad b value... retry', b)
        return solveDL()

    ret = []
    for prime in valid:
        if prime in primes or prime > 2**50 or prime in blacklist:
            continue
        try:
            # print(prime, E)
            # point = getPointDebug(*G.xy())
            G = E.gen(0) * int(order / prime)
            point = getPoint(*G.xy())
            P = E(point)
            log = G.discrete_log(P)
            print('prime:', prime, 'dlog:', log)
            ret.append((log, prime))
        except Exception as e:
            print(e)
            continue

    return ret




dlogs = []
primes = []
total = 1
while True:
    sols = solveDL()
    if sols is None:
        print('failed discrete log')
        continue

    for s in sols:
        dlogs.append(s[0])
        primes.append(s[1])
        total *= s[1]
    
    if total > 2**230:
        test = CRT(dlogs, primes)
        print('test:', test)
        print('total:', total)
        print('primes:', primes)
        print('dlogs:', dlogs)

    if total > 2**256:
        break