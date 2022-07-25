from collections import Counter
s = "﻿‌​​‌​​​⁠‌‌​​‌​‌⁠‌‌​‌‌​​⁠‌‌​‌‌​​⁠‌‌​‌‌‌‌⁠‌​​​​​⁠‌‌​​‌‌​⁠‌‌​​‌​‌⁠‌‌​‌‌​​⁠‌‌​‌‌​​⁠‌‌​‌‌‌‌⁠‌‌‌​‌‌‌⁠‌​​​​​⁠‌​​​​‌‌⁠‌‌​‌‌‌‌⁠‌‌​​‌​​⁠‌‌​​‌​‌⁠‌​‌​‌​​⁠‌‌​‌​​‌⁠‌‌​​‌‌‌⁠‌‌​​‌​‌⁠‌‌‌​​‌​⁠‌​​​​​⁠‌​​‌‌​​⁠‌‌​‌‌‌‌⁠‌‌‌‌​​‌⁠‌‌​​​​‌⁠‌‌​‌‌​​⁠‌‌​‌​​‌⁠‌‌‌​​‌‌⁠‌‌‌​‌​​⁠‌‌‌​​‌‌⁠‌​‌‌‌​⁠‌​​​​​⁠‌​​​‌​​⁠‌‌‌​‌​‌⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌‌​‌​​⁠‌‌​‌‌‌‌⁠‌​​​​​⁠‌‌​‌‌‌‌⁠‌‌‌​‌​‌⁠‌‌‌​​‌​⁠‌​​​​​⁠‌‌​‌​‌​⁠‌‌​‌‌‌‌⁠‌‌​‌​​‌⁠‌‌​‌‌‌​⁠‌‌‌​‌​​⁠‌​​​​​⁠‌‌​​‌​‌⁠‌‌​​‌‌​⁠‌‌​​‌‌​⁠‌‌​‌‌‌‌⁠‌‌‌​​‌​⁠‌‌‌​‌​​⁠‌​‌‌​​⁠‌​​​​​⁠‌‌​‌​​​⁠‌‌​‌​​‌⁠‌‌‌​​‌‌⁠‌​​​​​⁠‌‌​​‌​‌⁠‌‌‌​​‌‌⁠‌‌​​​‌‌⁠‌‌​​​​‌⁠‌‌‌​​​​⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌​‌​​​⁠‌‌​​​​‌⁠‌‌‌​​‌‌⁠‌​​​​​⁠‌‌​​​‌​⁠‌‌​​‌​‌⁠‌‌​​‌​‌⁠‌‌​‌‌‌​⁠‌​​​​​⁠‌‌‌​​‌‌⁠‌‌‌​‌​‌⁠‌‌​​​‌‌⁠‌‌​​​‌‌⁠‌‌​​‌​‌⁠‌‌‌​​‌‌⁠‌‌‌​​‌‌⁠‌‌​​‌‌​⁠‌‌‌​‌​‌⁠‌‌​‌‌​​⁠‌​‌‌‌​⁠‌​​​​​⁠‌​‌​‌​​⁠‌‌​‌​​​⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌​‌‌‌​⁠‌‌​‌‌‌‌⁠‌‌​‌‌‌​⁠‌​‌‌​‌⁠‌​​‌‌​​⁠‌‌​‌‌‌‌⁠‌‌‌‌​​‌⁠‌‌​​​​‌⁠‌‌​‌‌​​⁠‌‌​‌​​‌⁠‌‌‌​​‌‌⁠‌‌‌​‌​​⁠‌‌‌​​‌‌⁠‌​​​​​⁠‌‌​‌‌​‌⁠‌‌​​​​‌⁠‌‌‌‌​​‌⁠‌​​​​​⁠‌‌‌​‌​​⁠‌‌​‌​​​⁠‌‌​‌​​‌⁠‌‌​‌‌‌​⁠‌‌​‌​‌‌⁠‌​​​​​⁠‌‌​‌​​​⁠‌‌​‌​​‌⁠‌‌​‌‌​‌⁠‌​​​​​⁠‌‌​​‌‌‌⁠‌‌​‌‌‌‌⁠‌‌​‌‌‌​⁠‌‌​​‌​‌⁠‌​‌‌​​⁠‌​​​​​⁠‌‌​​​‌​⁠‌‌‌​‌​‌⁠‌‌‌​‌​​⁠‌​​​​​⁠‌‌‌​‌‌‌⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌​‌​‌‌⁠‌‌​‌‌‌​⁠‌‌​‌‌‌‌⁠‌‌‌​‌‌‌⁠‌​​​​​⁠‌‌‌​‌​​⁠‌‌​‌​​​⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌‌​‌​​⁠‌‌‌​​‌​⁠‌‌‌​‌​‌⁠‌‌‌​‌​​⁠‌‌​‌​​​⁠‌​‌‌‌​⁠‌​​​​​⁠‌​​‌​​​⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌​‌​​‌⁠‌‌‌​​‌‌⁠‌​​​​​⁠‌‌​‌‌​‌⁠‌‌​​‌​‌⁠‌‌‌​​‌​⁠‌‌​​‌​‌⁠‌‌​‌‌​​⁠‌‌‌‌​​‌⁠‌​​​​​⁠‌‌​‌‌​​⁠‌‌‌‌​​‌⁠‌‌​‌​​‌⁠‌‌​‌‌‌​⁠‌‌​​‌‌‌⁠‌​​​​​⁠‌‌​‌​​‌⁠‌‌​‌‌‌​⁠‌​​​​​⁠‌‌‌​‌‌‌⁠‌‌​​​​‌⁠‌‌​‌​​‌⁠‌‌‌​‌​​⁠‌​​​​​⁠‌‌‌​‌​​⁠‌‌​‌‌‌‌⁠‌​​​​​⁠‌‌‌​​‌​⁠‌‌​​‌​‌⁠‌‌‌​‌​​⁠‌‌‌​‌​‌⁠‌‌‌​​‌​⁠‌‌​‌‌‌​⁠‌​​​​​⁠‌‌‌​‌‌‌⁠‌‌​‌​​‌⁠‌‌‌​‌​​⁠‌‌​‌​​​⁠‌​​​​​⁠‌‌​​​​‌⁠‌‌​‌‌‌​⁠‌​​​​​⁠‌​​‌‌​​⁠‌​​‌​​‌⁠‌​‌​‌​​⁠‌​​​​​⁠‌‌‌​​​​⁠‌‌‌​​‌​⁠‌‌​‌‌‌‌⁠‌‌​​​‌​⁠‌‌​‌‌​​⁠‌‌​​‌​‌⁠‌‌​‌‌​‌⁠‌​​​​​⁠‌‌‌​‌​​⁠‌‌​‌‌‌‌⁠‌​​​​​⁠‌‌​​‌​​⁠‌‌​​​​‌⁠‌‌‌‌​‌​⁠‌‌‌‌​‌​⁠‌‌​‌‌​​⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌‌​‌​‌⁠‌‌‌​​‌‌⁠‌​​​​​⁠‌‌​​​​‌⁠‌‌​‌‌​​⁠‌‌​‌‌​​⁠‌​‌‌‌​⁠‌​​​​​⁠‌​​‌‌​​⁠‌‌​​‌​‌⁠‌‌‌​‌​​⁠‌​​​​​⁠‌‌​‌​​‌⁠‌‌‌​‌​​⁠‌​​​​​⁠‌‌​​​‌​⁠‌‌​​‌​‌⁠‌​​​​​⁠‌‌​‌​‌‌⁠‌‌​‌‌‌​⁠‌‌​‌‌‌‌⁠‌‌‌​‌‌‌⁠‌‌​‌‌‌​⁠‌‌‌​‌​⁠‌‌​‌⁠‌​‌​⁠‌‌​‌⁠‌​‌​⁠‌​​​​‌‌⁠‌‌​​​​⁠‌‌​​‌​​⁠‌​​​‌​‌⁠‌‌‌​‌​​⁠‌‌​​​‌⁠‌​​​‌‌‌⁠‌‌​​‌​‌⁠‌​‌​​‌​⁠‌​‌‌‌‌‌⁠‌​​‌‌​​⁠‌‌​​​‌⁠‌​‌​‌‌​⁠‌​​​‌​‌⁠‌​‌​​‌‌﻿"
print(len(s))
c = Counter(s)
print(c)

s = s[1:-1]
s = s.split("\u2060")
print(len(s))
print(list(len(i) for i in s))

dict = {"\u200b": "0", "\u200c": "1"}
msg = []
for i in s:
    t = []
    for j in i:
        t.append(dict[j])
    byte = int("".join(t), 2)
    msg.append(chr(byte))
print("".join(msg))