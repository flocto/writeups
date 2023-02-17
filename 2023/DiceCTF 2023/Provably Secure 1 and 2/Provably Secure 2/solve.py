from pwn import *
from tqdm import tqdm
# nc mc.ax 31497
r = remote('mc.ax', 31497)

for i in tqdm(range(128)):
    r.recvuntil(b'Action:')
    r.sendline(b'1')
    r.recvuntil(b'm0 (16 byte hexstring):')
    r.sendline(b'0'*32)
    r.recvuntil(b'm1 (16 byte hexstring):')
    r.sendline(b'0'*31 + b'1')

    ct1 = r.recvline().strip()

    r.recvuntil(b'Action:')
    r.sendline(b'1')
    r.recvuntil(b'm0 (16 byte hexstring):')
    r.sendline(b'0'*32 )
    r.recvuntil(b'm1 (16 byte hexstring):')
    r.sendline(b'0'*31 + b'2')

    ct2 = r.recvline().strip()

    dt1 = ct1[:512] + ct2[512:]
    dt2 = ct2[:512] + ct1[512:]

    r.recvuntil(b'Action:')
    r.sendline(b'2')
    r.recvuntil(b'ct (512 byte hexstring):')
    r.sendline(dt1)

    m1 = r.recvline().strip()

    r.recvuntil(b'Action:')
    r.sendline(b'2')
    r.recvuntil(b'ct (512 byte hexstring):')
    r.sendline(dt2)

    m2 = r.recvline().strip()
    m = int(m1 != m2)

    r.recvuntil(b'Action:')
    r.sendline(b'0')
    r.recvuntil(b'm_bit guess:')
    r.sendline(str(m).encode())

r.interactive()
