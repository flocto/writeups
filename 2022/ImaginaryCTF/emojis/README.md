# Emojis
## Description
>To be or not to be, that is the question. Sadly the challenge doesn't look nearly as good unless you have a fancy terminal 😦

## Attachments
> [emojis.txt](emojis.txt)
> 
# 👍👎
All we're given is a single text file. Inside the file, there seems to be a bunch of :+1: and :-1: emojis.
```
👎👍👍👎👍👎👎👍👎👍👍👎👎👎👍👍👎👍👍👍...(truncated)
```
Let's try analyzing the entire thing in python
```python
uniq = set()
with open("emojis.txt", "rb") as f:
    emojis = f.read().decode("utf-8")
for e in emojis:
    uniq.add(e)
print(uniq)
print(len(emojis))
>>> {'👎', '👍'}
>>> 328
```
We see that there are only two unique emojis, and there is 328 emojis total.

It seems this is a simple binary encoding. There are only 2 values, and the total length is divisible by 8. That means each
8 emojis would represent a single byte/character of the flag. But how do we go about telling which emoji is 1 and which is 0?
## Careful analysis
After lots of careful analysis, I came to the conclusion that :+1: probably represented a 1 because it has a positive connotation.
Therefore :-1: must be a 0.

# Solution
All we have to do now is properly translate each bit, then converts those bits into bytes/plaintext, and we should have the flag!
```
uniq = set()
with open("emojis.txt", "rb") as f:
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
```
No. Wait. Something still feels wrong. We can't solve it like this!

# The REAL Solution
Python has nothing to do with emojis!? Emojis have everything to do with emojis!

Why cheat yourself out of the real solution?
```
📦 files 🏠
🏁 🍇
    🍿
        🔤👎🔤 ➡️ 🔤0🔤
        🔤👍🔤 ➡️ 🔤1🔤
    🍆 ➡️ dict

    🍺🆕📄▶️📜 🔤emojis.txt🔤❗️ ➡️ readFile
    🍺📓readFile 1312❗️ ➡️ t 
    🍺🔡t❗️ ➡️ emojis
    🆕🔠❗️ ➡️ tbits 

    🔂 c emojis 🍇
        ↪️ 🐽dict c❗️ ➡️ char 🍇
            🐻tbits char❗️
        🍉
    🍉
    🔡tbits❗️ ➡️ bits

    🆕🔠❗️ ➡️ msg
    🔂 i 🆕⏩ 0 328 8❗️ 🍇 
        💧🍺🔢🔪bits i 8❗️ 2❗️ ❗️ ➡️ byte
        ☣️️🍇
            🐻🔸💧 msg byte❗️
        🍉
    🍉
    😀🔡msg❗️ ❗️
🍉
```
I'm not going to explain how to install or set up emojicode, but you can follow [this guide.](https://www.emojicode.org/docs/guides/)

But I will explain what happens. If you don't an explanation and just want the actual solution, just look up.

# Explanation
Obviously all of the important syntax is in emojis. `🏁` defines the main statement, like in C/C++, that runs when the program is executed. `🍇` and `🍉` open and close a block
respectively, acting similar to `{}`. Functions can be defined with any emoji, and accept arguments up to ❗️. (There also exist ❓ functions, but I don't use them here)
```
🏁 🍇
    🍿
        🔤👎🔤 ➡️ 🔤0🔤
        🔤👍🔤 ➡️ 🔤1🔤
    🍆 ➡️ dict
```
This first bit of code defines a collection literal using `🍿`. In this case, two key-value pairs are defined, making the collection a dictionary. 

The first key-value pair matches the string `'👎'` (denoted by `🔤`) to another string `'0'`. The `➡️` is what makes the connection.<br/>
The second pair maps `'👍'` to `'1'`.<br/>
Finally, the entire dictionary is stored in a variable called `dict`.

```
🍺🆕📄▶️📜 🔤emojis.txt🔤❗️ ➡️ readFile
🍺📓readFile 1312❗️ ➡️ t 
🍺🔡t❗️ ➡️ emojis
🆕🔠❗️ ➡️ tbits 
```
This bit of code first creates a filereader using the `file` package. <br />
If you noticed earlier, before the main function declaration, there was a line of code containing `📦 files 🏠`.
This code essentially imports the file package to the namespace of the current file, similar to `import` from other languages.

`🍺🆕📄▶️📜 🔤emojis.txt🔤❗️ ➡️ readFile` is pretty complicated, but essentially it just reads from the [emojis.txt](emojis.txt) file and stores 
the file reader into `readFile`.

`🍺📓readFile 1312❗️ ➡️ t ` then reads out 1312 bytes from `readFile` (each emoji is 4 bytes, there are 328 total), and stores the byte array
into `t`.

Finally, `🍺🔡t❗️ ➡️ emojis` reads the string represented by the byte array and stores that into `emojis`.

At the end, `🆕🔠❗️ ➡️ tbits ` defines a new variable called `tbits`. This acts like a StringBuilder from Java if you're familiar with those, but basically
it's just a mutable string. Notice the difference between `🔠` and `🔡`. The former is the string builder, while the latter is the built-in immutable string.

If you've noticed all the `🍺`s, that's because those unwrap values from optionals. If you know a bit of Rust, optionals are very similar to Option. These functions
are not guaranteed to return an output, which is why they have to be unwrapped before they can be stored.

```
🔂 c emojis 🍇
        ↪️ 🐽dict c❗️ ➡️ char 🍇
            🐻tbits char❗️
        🍉
    🍉
🔡tbits❗️ ➡️ bits
```
Now, we iterate over all the characters in emoji using the for-in loop `🔂`. For each character, we select the matching string from the dictionary we defined earlier
using 🐽, and store that result in `char`. 

If (`↪️`) `char` is not null/empty, we use `🐻` to append `char` to the end of `tbits`.<br/>
After iterating over all the values in emojis, `tbits` is converted from a string builder to just a string, and stored in `bits`.

At this point, bits contains the converted emojis to 1's and 0's.
```
🆕🔠❗️ ➡️ msg
🔂 i 🆕⏩ 0 328 8❗️ 🍇 
    💧🍺🔢🔪bits i 8❗️ 2❗️ ❗️ ➡️ byte
    ☣️️🍇
        🐻🔸💧 msg byte❗️
    🍉
🍉
```
Now we create another string builder called `msg` which will store the final output.

We iterate `🔂` over each `i` in the range `⏩` `0 328 8`. This is similar to the Python `range()`, using start, stop, and step.
This allows us to take 8 bits as a time from `bits`.

We then perform a pretty complex operation. First, `🔪bits i 8❗️` returns a substring from `i` to `i+8` from `bits`. <br/>
Then, `🍺🔢x 2❗️` (x being what we just computed) generates an integer in the specified base from the supplied string.
In this case, it reads the binary and converts it into an integer from base 2. Of course, we also have to unwrap this value with `🍺`<br/>
Finally, `💧x ❗️` converts the integer into a byte and stores it in `byte`.

The next section is defined as an unsafe block using `☣️`. This is similar to Rust's unsafe as well.<br/>
Inside the unsafe block, we append `byte` to `msg` as a pure byte using `🐻🔸💧 ❗️`

```
😀🔡msg❗️ ❗️
```
Finally, at the very end, all we have to do is convert `msg` from a string builder to a pure string, and print it out using `😀 ❗️`.<br />
Because the bytes were appended as raw bytes, they get converted into ascii and thus are printed properly.

## Flag
```bash
>>> emojicodec REALSOLVE.🍇
>>> ./REALSOLVE
ictf{enc0ding_is_n0t_encrypti0n_1b2e0d43}
```
If you want to run the program yourself without compiling, you have to download both [REALSOLVE](REALSOLVE) and [REALSOLVE.o](REALSOLVE.o)

# Conclusion
Cool basic challenge, and I totally did not learn an esolang to "correctly" solve it.

Thanks for reading!