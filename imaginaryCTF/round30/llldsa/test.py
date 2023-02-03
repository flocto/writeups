from Crypto.Util.Padding import pad
from Crypto.Util.number import isPrime, getPrime, long_to_bytes
from Crypto.Cipher import AES
from hashlib import sha256
from random import randrange

c = '3c5f1079e0d30abf35d059ffea0ac6b460c1cd372d5622ede50df037f733015f'
c = bytes.fromhex(c)

x = 3278213471492904754553833673944897982935105139828155475166434382168177337280321867717755120
