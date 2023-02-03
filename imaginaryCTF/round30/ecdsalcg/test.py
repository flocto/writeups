from Crypto.Util.number import getPrime
from Crypto.Cipher import AES
from hashlib import sha256
from secrets import randbelow


d = 83997230671504838806972202409692819984821818663940197945458617688520105873165
ct = b'\xe6\x9c\xcaZ\x01\x90-\xa0\xbc8\xeb\xe4\xc6\xc7b\x16\xb9t++@\xc0\x0ce\t\x9e\xb5\x07p\xe49*\xb8\xce\xfe@\xea%\xc9\xd6\xefF\xf8\x7fQ\x9bg\xbd\x7f\xcf{h\\^\x11\xf9\xf5\xe8\x7f}\x94\xd3+\x06\x19.`\x84\x8d)\x1e\xdey\xe4 [\x9e'
nonce = b'Z\x1c\xba\xbc\x95\\\xe1u'

key = sha256(str(d).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
print(nonce, cipher.nonce)
print(f"{cipher.decrypt(ct) = }")