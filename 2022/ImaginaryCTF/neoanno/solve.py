import pwn
#nc neoannophobia.chal.imaginaryctf.org 1337
s = pwn.remote('neoannophobia.chal.imaginaryctf.org', 1337)
d = 31
months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
dayWin = {}
monthWin = {}
for i in range(12):
    dayWin[months[12-i-1]] = d
    monthWin[d] = months[12-i-1]
    d -= 1
for i in range(100):
    s.recvuntil(b'ROUND ' + (str(i+1)+"\n").encode())
    s.recvline()
    print(i)
    line = s.recvuntil(b'> ')
    line = line.decode().split()
    # print(line)
    dayWin = int(line[1])
    month = line[0]
    while dayWin != 31 and month != "December":
        target = dayWin[month]
        if dayWin < target:
            msg = month + " " + str(target) + "\n"
            s.send_raw(msg.encode())
        elif dayWin > target:
            month = monthWin[dayWin]
            msg = month + " " + str(dayWin) + "\n"
            s.send_raw(msg.encode())
        else:
            dayWin += 1
            msg = month + " " + str(dayWin) + "\n"
            s.send_raw(msg.encode())
        line = s.recvuntil(b'> ')
        line = line.decode().split()
        # print(line)
        dayWin = int(line[1])
        month = line[0]
    s.send_raw(b"December 31\n")
s.interactive()

# ictf{br0ken_game_smh_8b1f014a}