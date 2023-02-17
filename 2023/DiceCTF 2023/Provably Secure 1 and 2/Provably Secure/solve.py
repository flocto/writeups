from pwn import *
from tqdm import tqdm
# nc mc.ax 31493
r = remote('mc.ax', 31493)

for i in tqdm(range(128)):
    r.recvuntil(b'Action:')
    r.sendline(b'1')
    r.recvuntil(b'm0 (16 byte hexstring):')
    r.sendline(b'0'*32)
    r.recvuntil(b'm1 (16 byte hexstring):')
    r.sendline(b'0'*31 + b'1')

    ct = r.recvline().strip()

    r.recvuntil(b'Action:')
    r.sendline(b'2')
    r.recvuntil(b'ct (512 byte hexstring):')
    r.sendline(ct)

    m = r.recvline().strip()
    m = int(m) # 0 or 1

    r.recvuntil(b'Action:')
    r.sendline(b'0')
    r.recvuntil(b'm_bit guess:')
    r.sendline(str(m).encode())

r.interactive()
