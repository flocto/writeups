import ctypes
from Crypto.Util.number import long_to_bytes, bytes_to_long

# https://gist.github.com/twheys/4e83567942172f8ba85058fae6bfeef5
def _decipher(v, k):
    """
    TEA decipher algorithm.  Decodes a length-2 vector using a length-4 vector as a length-2 vector.
    """
    y, z = [ctypes.c_uint32(x)
            for x in v]
    sum = ctypes.c_uint32(0xC6EF3720)
    delta = 0x9E3779B9

    for n in range(32, 0, -1):
        z.value -= ((y.value << 4) + k[2]) ^ (y.value + sum.value) ^ ((y.value >> 5) + k[3])
        y.value -= ((z.value << 4) + k[0]) ^ (z.value + sum.value) ^ ((z.value >> 5) + k[1])
        sum.value -= delta

    return [y.value, z.value]

enc = open("flag.enc", "rb").read()
enc = [bytes_to_long(enc[i:i+4][::-1]) for i in range(0, len(enc), 4)]

key = [100, 200, 300, 400]

dec = b""

for i in range(0, len(enc), 2):
    a, b = _decipher(enc[i:i+2], key)
    dec += long_to_bytes(a)[::-1] + long_to_bytes(b)[::-1]

print(dec)