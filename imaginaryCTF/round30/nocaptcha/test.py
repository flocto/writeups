import base64
import zlib

cookie = '.eJwVzLEKwjAQgOF3udlA0lySO1eHbi4qRRfJ5XogQitaJ_Hdrds_fPwfaPUBW-h2ZV-Yz5fjkAMNhxP2PWygze9pgW1c6_W06zLfx2nVjVjIV0YRK8pjYM4iEUdTokBdKpa9RlsPN_17JFNJ2VloyaF471hSdRkFq0WvLSp8f_qNJ2c.Y9mKnA.q3iXXHxS61khIuTzNi-wdw-Ovy8'
cookie = cookie.split('.')
print(cookie)
cookie = cookie[1] + '=' + '='
cookie = base64.urlsafe_b64decode(cookie)
print(cookie)
cookie = zlib.decompress(cookie)
print(cookie)