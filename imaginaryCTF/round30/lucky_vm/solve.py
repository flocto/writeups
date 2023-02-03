data = list(open('bin','rb').read())
mem = [0] * 0x10000
i = 0
CLOCK = 0

def inst_02_addconst(a, b, c):
    mem[a] = mem[b] + c

def inst_04_subconst(a, b, c):
    mem[a] = mem[b] - c

def inst_0d_xormem(a, b, c):
    mem[a] = mem[b] ^ mem[c]

def inst_11_load_data_mem(a, b, c):
    data[mem[a]] = mem[b]

def inst_13_store_data_mem(a, b, c):
    mem[a] = data[mem[b]]

def inst_14_store_data_const(a, b, c):
    mem[a] = data[b]

def inst_19_jmp_ifnotequal(a, b, c):
    global i
    if mem[b] != mem[c]:
        i = a
        return i

def inst_1a_exit(a, b, c):
    print('exit')
    # print(a, b, c)
    # print(mem)
    # print(data)
    print(CLOCK)
    exit()


def scan_mem():
    mem_ascii = ''.join([chr(x) for x in mem if 33 <= x <= 127])
    if 'ictf' in mem_ascii:
        print('found flag in mem at', CLOCK)
        print(mem_ascii)
        print(mem) 
    
    data_ascii = ''.join([chr(x) for x in data if 33 <= x <= 127])
    if 'ictf' in data_ascii:
        print('found flag in data at', CLOCK)
        print(data_ascii)
        # print(data)


insts = {
    0x02: inst_02_addconst,
    0x04: inst_04_subconst,
    0x0d: inst_0d_xormem,
    0x11: inst_11_load_data_mem,
    0x13: inst_13_store_data_mem,
    0x14: inst_14_store_data_const,
    0x19: inst_19_jmp_ifnotequal,
    0x1a: inst_1a_exit,
}


while True:
    inst = data[i]
    if inst > 0x1a:
        print('illegal instruction')
        break

    params = data[i+1:i+7] # next 6 bytes
    a = int.from_bytes(params[0:2], 'little')
    b = int.from_bytes(params[2:4], 'little')
    c = int.from_bytes(params[4:6], 'little')
    # print('instruction: %02x' % inst, end=' ')
    # print('params: %02x %02x %02x %02x %02x %02x' % tuple(params), end=' ')
    # print('rip: %02x' % i)
    # print('mem:', mem[:0x10])
    # print('data:', data[:0x10])
    rip = insts[inst](a, b, c)
    CLOCK += 1
    scan_mem()
    if rip:
        i = rip
    else:
        i += 7
