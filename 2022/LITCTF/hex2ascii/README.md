# Hex to ASCII
## Description
> Do you know how to speak hexadecimal? I love speaking in hexadecimal. In fact, in HexadecimalLand, we like to say
## Attachments
> 4c49544354467b74306f6c355f346e645f77336273317433735f6172335f763372795f696d70307274346e745f6630725f4354467d
---
# No joke
This is a pretty simple task, a quick google search solves it instantly, it's just a conversion of hex
to string (in ASCII).

## Okay maybe one joke.
I'm going to start a tradition upsolving easy problems in emojicode because its pretty funny lol.
```
🏁 🍇
    🔤4c49544354467b74306f6c355f346e645f77336273317433735f6172335f763372795f696d70307274346e745f6630725f4354467d🔤 ➡️ hex
    🆕🔠❗️ ➡️ msg
    🔂 i 🆕⏩ 0 📐hex❗️ 2❗️ 🍇
        💧🍺🔢🔪hex i 2❗️ 16❗️ ❗️ ➡️ char
        ☣️️🍇
            🐻🔸💧 msg char❗️
        🍉
    🍉
    😀🔡msg❗️ ❗️
🍉
```
If you read my [first emojicode writeup](https://github.com/flocto/writeups/tree/main/2022/ImaginaryCTF/emojis) this one is
quite similar to the last part of that one.

Basically I define a string literal `hex` with the given input. Then I iterate over the range of that literal with a step of 2. <br/>
On each iteration, I take a slice of 2 characters, read that slice as a number using base 16, and finally store that number as a byte
in `char`. <br/>
`char` is then appended to `msg`, a string builder defined earlier. 

After all the iterations, the entire message should be properly decoded in `msg`, meaning we can just print it out.

Running the program, we get our flag.
```
>>> emojicodec hex2ascii.🍇
>>> ./hex2ascii
LITCTF{t0ol5_4nd_w3bs1t3s_ar3_v3ry_imp0rt4nt_f0r_CTF}
```
