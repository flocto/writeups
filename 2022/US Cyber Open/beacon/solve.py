import sympy

with open('data.json', 'r') as f:
    data = f.read().splitlines()

data = [x[1:-1].split(',') for x in data]
print(data)

Nlist = []
Elist = []
Clist = []
for line in data:
    for x in line:
        x = x.strip()
        x = x.split('": ')
        x[0] = x[0][1:]
        if x[0] == 'n':
            Nlist.append(int(x[1]))
        elif x[0] == 'e':
            Elist.append(int(x[1]))
        elif x[0] == 'msg':
            Clist.append(int(x[1]))

# for i in range(len(Nlist)):
#     for j in range(i+1, len(Nlist)):
#         n1 = Nlist[i]
#         n2 = Nlist[j]
#         if sympy.gcd(n1, n2) != 1:
#             print(i, j)
#             break

i = 5
j = 29
n1 = Nlist[i]
n2 = Nlist[j]
q = sympy.gcd(n1, n2)
p = n1 // q
d = sympy.mod_inverse(Elist[i], (p-1)*(q-1))
m = pow(Clist[i], d, n1)
m = bytes.fromhex(hex(m)[2:]).decode('utf-8')
print(m)