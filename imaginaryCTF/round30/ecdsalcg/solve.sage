from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from fastecdsa.curve import secp256k1
from hashlib import sha256
from secrets import randbelow

G = secp256k1.G
a, b = G.x, G.y
q = secp256k1.q

p = 9927040122486684509203958106419420141058188722199373989012953585197167125223276141324574147521754273735827724127795605194092299982453828901469369136978219
sigs = [(98078224267884884220741740422077019843954009281647502734600509731511013529371, 54523865988310606978987830048871561792183822750263202533230451076893555969316), (104372973739209868434840748268723094332969140159620819033951611727659419363988, 39660851627725578124743718742328950528148285144862142963822549722002689280409),
        (103919709879086855178251181244489637133481828592253195107866903154222896468253, 35031204282583023574328215246485186335362731664384171126097342931654133207246), (63175283280752608661708773461972110889312169792285211062806717970617630555061, 34712080692439206749112321272818736084925608248138548106200594874651099131535)]
msgs = [
    b"https://www.youtube.com/watch?v=S8MJvhgjXBY",
    b"https://www.youtube.com/watch?v=wSTbdqo-j74",
    b"https://www.youtube.com/watch?v=dkYHgxfQZBA",
    b"https://www.youtube.com/watch?v=p8ET-m6y6VU",
]
ct = b'\xe6\x9c\xcaZ\x01\x90-\xa0\xbc8\xeb\xe4\xc6\xc7b\x16\xb9t++@\xc0\x0ce\t\x9e\xb5\x07p\xe49*\xb8\xce\xfe@\xea%\xc9\xd6\xefF\xf8\x7fQ\x9bg\xbd\x7f\xcf{h\\^\x11\xf9\xf5\xe8\x7f}\x94\xd3+\x06\x19.`\x84\x8d)\x1e\xdey\xe4 [\x9e'
nonce = b'Z\x1c\xba\xbc\x95\\\xe1u'

def H(m):
    return int.from_bytes(sha256(m).digest(), "big")

def lcg_step(x):
    return (a * x + b) % p

def sign(d, z, k):
    r = (int(k) * G).x
    s = (z + r * d) / k % q
    return r, s

def verify(P, z, r, s):
    u1 = z * pow(s, -1, q) % q
    u2 = r * pow(s, -1, q) % q
    x = (int(u1) * G + int(u2) * P).x
    print("x =", x)
    print("r =", r)
    return x == r


r1, r2, r3, r4 = [s[0] for s in sigs]
s1, s2, s3, s4 = [s[1] for s in sigs]
m1, m2, m3, m4 = [H(m) for m in msgs]

def Babai_closest_vector(M, G, target):
    # Babai's Nearest Plane algorithm
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

xp = q/2
k1p = k2p = p/2
gx = min(xp, q-xp)
gk1 = min(k1p, p-k1p)
gk2 = min(k2p, p-k2p)

B = Matrix([
    [-r1, -r2, -r3, -r4,     0,     0,     0,  1/gx,     0,     0,     0,     0],
    [ s1,   0,   0,   0,    -a,     0,     0,     0, 1/gk1,     0,     0,     0],
    [  0,  s2,   0,   0,     1,    -a,     0,     0,     0, 1/gk2,     0,     0],
    [  0,   0,  s3,   0,     0,     1,    -a,     0,     0,     0, 1/gk2,     0],
    [  0,   0,   0,  s4,     0,     0,     1,     0,     0,     0,     0, 1/gk2],
    [  q,   0,   0,   0,     0,     0,     0,     0,     0,     0,     0,     0],
    [  0,   q,   0,   0,     0,     0,     0,     0,     0,     0,     0,     0],
    [  0,   0,   q,   0,     0,     0,     0,     0,     0,     0,     0,     0],
    [  0,   0,   0,   q,     0,     0,     0,     0,     0,     0,     0,     0],
    [  0,   0,   0,   0,     p,     0,     0,     0,     0,     0,     0,     0],
    [  0,   0,   0,   0,     0,     p,     0,     0,     0,     0,     0,     0],
    [  0,   0,   0,   0,     0,     0,     p,     0,     0,     0,     0,     0],
])

Y = vector([m1, m2, m3, m4, b, b, b, xp/gx, k1p/gk1, k2p/gk2, k2p/gk2, k2p/gk2])
# show(B)

M = B.LLL()
# show(M)
Gr = M.gram_schmidt()[0]

W = Babai_closest_vector(M, Gr, Y)
show(Y[:7])
show(W)

assert(Y[:7] == W[:7])

x = W[7] * gx % q
k1 = W[8] * gk1 % p
k2 = W[9] * gk2 % p

print("q =", q)
print("x =", x)
print("k1 =", k1)
print("k2 =", k2)
print("test lcg", lcg_step(x))
print()

x = int(x)

print(m1 == (s1 * k1 - r1 * x) % q)
print(m2 == (s2 * k2 - r2 * x) % q)
print(b == (-a * k1 + k2) % p)
print()

# wtv just try
test_x = (s1 * k1 - m1) * pow(r1, -1, q) % q
print(test_x, test_x == x)

P = x * G
nonces = [k1, k2]
while len(nonces) < 4:
    nonces.append(lcg_step(nonces[-1]))

for m, r, s, k in zip([m1, m2, m3, m4], [r1, r2, r3, r4], [s1, s2, s3, s4], nonces):
    print(sign(x, m, k) == (r, s))
    print(verify(P, m, r, s))
    print()
print()
d = x
print(str(x))
key = sha256(str(d).encode()).digest()[:16]
print(key, nonce)
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
print(cipher.decrypt(ct))

