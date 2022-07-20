uniq = set()
with open("test.txt", "rb") as f:
    emojis = f.read().decode("utf-8")
for e in emojis:
    uniq.add(e)
print(uniq)
print(len(emojis))

dict = {'👎': 0, '👍': 1}
msg = ""
for i in range(len(emojis)//8):
    num = emojis[i*8:i*8+8]
    num = [dict[x] for x in num]
    num = int("".join(str(x) for x in num), 2)
    msg += chr(num)
print(msg)

# ictf{enc0ding_is_n0t_encrypti0n_1b2e0d43}