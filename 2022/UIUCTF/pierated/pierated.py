import io
import pwn
#nc pierated-art.chal.uiuc.tf 1337
s = pwn.remote('pierated-art.chal.uiuc.tf', 1337)
# base64 to image
from PIL import Image
import base64
import os
import time
for i in range(10):
    s.recvline_contains(b'(Base64):')
    img = s.recvline().decode('utf-8')
    # print(img[:10], img[-10:])
    img = base64.b64decode(img)
    img = Image.open(io.BytesIO(img))
    img = img.convert('RGB')
    filename = 'img.png'
    img.save(filename)
    os.system('repiet -o out.py -b python '+filename)
    time.sleep(2)
    code = open("out.py","r").read()
    lines = code.split("\n")
    # comp = compile(code, 'code', 'exec')
    # find function labeled X56y3
    f = 0
    for line in lines:
        if "def X56y3():" in line:
            f = lines.index(line)
            break
    f = lines[f+1].split(" ")[-1]
    print(f)
    g = 0
    for line in lines:
        if "def "+f+"():" in line:
            g = lines.index(line)
            break
    msg = ""
    print(g)
    while True:
        g = g + 4 + 4 + 5
        num = int(lines[g+1].split("(")[-1].replace(")",""))
        # print(num)
        for i in range(ord('a'), ord('z')+1):
            if (i + num) % 26 == 0:
                msg += chr(i)
                break
        g = g+4+5+4+5+5+5
        if "print" in lines[g+2]:
            break
        g += 3
        # print(g)
    msg = msg[::-1]
    print(msg)
    s.sendline(msg.encode('utf-8'))
s.interactive()