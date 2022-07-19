import pwn
# 0.cloud.chals.io on:11444

with open("egg.txt", "r") as f:
    data = f.read()

edges = {}
for i, line in enumerate(data.split("\n")):
    if line == "":
        continue
    edges[i] = eval(line)


s = pwn.remote('0.cloud.chals.io', 11444)

s.recvline_contains(b'Username:')
s.send_raw(b'mgrey\n')
s.recvline_contains(b'Password:')
s.send_raw(b'1515\n')

for i in range(15):
    guesses = set()
    solved = False
    lasttrust = 0
    trust = 0
    lastguess = -1
    guess = 0

    while not solved:
        # print("a")
        line = s.recvline_contains(b'Enter')
        line = line.decode('utf-8').strip().split(' ')
        # print(line)
        lasttrust = trust
        trust = int(line[-1][:-2])
        # print(trust)
        if i == 0 and lasttrust - trust == 1:
            print(lastguess, guess)
        # print(lastguess, guess, lasttrust - trust)
        lastguess = guess
        guess = -1
        for j in edges[lastguess]:
            if j in guesses:
                continue
            guess = j
        if guess == -1:
            print("fail")
            exit()
        guesses.add(guess)
        #print("size", len(guesses))
        g = str(guess).rjust(3, '0').encode('utf-8') + b'\n'
        # print(g)
        s.send_raw(g)
        line = s.recvline()
        # print(line)
        if line == b'Correct Code\n':
            print(line)
            solved = True


# with open("graph.txt", "w") as f:
    # f.write(str(edges))
s.interactive()
