code = open("out.py","r").read()
lines = code.split("\n")
comp = compile(code, 'code', 'exec')
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
kvals = []
print(g)
while True:
    g = g + 4 + 4 + 5
    k = int(lines[g+1].split("(")[-1].replace(")",""))
    print(k)
    kvals.append(k)
    g = g+4+5+4+5+5+5
    if "print" in lines[g+2]:
        break
    g += 3
    # print(g)
print(kvals[::-1])
msg = ""
for k in kvals[::-1]:
    for c in 'abcdefghijklmnopqrstuvwxyz':
        if (ord(c)+k)%26 == 0:
            msg += c
            break
print(msg)