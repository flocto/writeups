# Emojis
## Description
>To be or not to be, that is the question. Sadly the challenge doesn't look nearly as good unless you have a fancy terminal π¦

## Attachments
> [emojis.txt](emojis.txt)
> 
# ππ
All we're given is a single text file. Inside the file, there seems to be a bunch of :+1: and :-1: emojis.
```
ππππππππππππππππππππ...(truncated)
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
>>> {'π', 'π'}
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
```python
uniq = set()
with open("emojis.txt", "rb") as f:
    emojis = f.read().decode("utf-8")
for e in emojis:
    uniq.add(e)
print(uniq)
print(len(emojis))

dict = {'π': 0, 'π': 1}
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
π¦ files π 
π π
    πΏ
        π€ππ€ β‘οΈ π€0π€
        π€ππ€ β‘οΈ π€1π€
    π β‘οΈ dict

    πΊππβΆοΈπ π€emojis.txtπ€βοΈ β‘οΈ readFile
    πΊπreadFile 1312βοΈ β‘οΈ t 
    πΊπ‘tβοΈ β‘οΈ emojis
    ππ βοΈ β‘οΈ tbits 

    π c emojis π
        βͺοΈ π½dict cβοΈ β‘οΈ char π
            π»tbits charβοΈ
        π
    π
    π‘tbitsβοΈ β‘οΈ bits

    ππ βοΈ β‘οΈ msg
    π i πβ© 0 328 8βοΈ π 
        π§πΊπ’πͺbits i 8βοΈ 2βοΈ βοΈ β‘οΈ byte
        β£οΈοΈπ
            π»πΈπ§ msg byteβοΈ
        π
    π
    ππ‘msgβοΈ βοΈ
π
```
I'm not going to explain how to install or set up emojicode, but you can follow [this guide.](https://www.emojicode.org/docs/guides/)

But I will explain what happens. If you don't an explanation and just want the actual solution, just look up.

# Explanation
Obviously all of the important syntax is in emojis. `π` defines the main statement, like in C/C++, that runs when the program is executed. `π` and `π` open and close a block
respectively, acting similar to `{}`. Functions can be defined with any emoji, and accept arguments up to βοΈ. (There also exist β functions, but I don't use them here)
```
π π
    πΏ
        π€ππ€ β‘οΈ π€0π€
        π€ππ€ β‘οΈ π€1π€
    π β‘οΈ dict
```
This first bit of code defines a collection literal using `πΏ`. In this case, two key-value pairs are defined, making the collection a dictionary. 

The first key-value pair matches the string `'π'` (denoted by `π€`) to another string `'0'`. The `β‘οΈ` is what makes the connection.<br/>
The second pair maps `'π'` to `'1'`.<br/>
Finally, the entire dictionary is stored in a variable called `dict`.

```
πΊππβΆοΈπ π€emojis.txtπ€βοΈ β‘οΈ readFile
πΊπreadFile 1312βοΈ β‘οΈ t 
πΊπ‘tβοΈ β‘οΈ emojis
ππ βοΈ β‘οΈ tbits 
```
This bit of code first creates a filereader using the `file` package. <br />
If you noticed earlier, before the main function declaration, there was a line of code containing `π¦ files π `.
This code essentially imports the file package to the namespace of the current file, similar to `import` from other languages.

`πΊππβΆοΈπ π€emojis.txtπ€βοΈ β‘οΈ readFile` is pretty complicated, but essentially it just reads from the [emojis.txt](emojis.txt) file and stores 
the file reader into `readFile`.

`πΊπreadFile 1312βοΈ β‘οΈ t ` then reads out 1312 bytes from `readFile` (each emoji is 4 bytes, there are 328 total), and stores the byte array
into `t`.

Finally, `πΊπ‘tβοΈ β‘οΈ emojis` reads the string represented by the byte array and stores that into `emojis`.

At the end, `ππ βοΈ β‘οΈ tbits ` defines a new variable called `tbits`. This acts like a StringBuilder from Java if you're familiar with those, but basically
it's just a mutable string. Notice the difference between `π ` and `π‘`. The former is the string builder, while the latter is the built-in immutable string.

If you've noticed all the `πΊ`s, that's because those unwrap values from optionals. If you know a bit of Rust, optionals are very similar to Option. These functions
are not guaranteed to return an output, which is why they have to be unwrapped before they can be stored.

```
π c emojis π
        βͺοΈ π½dict cβοΈ β‘οΈ char π
            π»tbits charβοΈ
        π
    π
π‘tbitsβοΈ β‘οΈ bits
```
Now, we iterate over all the characters in emoji using the for-in loop `π`. For each character, we select the matching string from the dictionary we defined earlier
using π½, and store that result in `char`. 

If (`βͺοΈ`) `char` is not null/empty, we use `π»` to append `char` to the end of `tbits`.<br/>
After iterating over all the values in emojis, `tbits` is converted from a string builder to just a string, and stored in `bits`.

At this point, bits contains the converted emojis to 1's and 0's.
```
ππ βοΈ β‘οΈ msg
π i πβ© 0 328 8βοΈ π 
    π§πΊπ’πͺbits i 8βοΈ 2βοΈ βοΈ β‘οΈ byte
    β£οΈοΈπ
        π»πΈπ§ msg byteβοΈ
    π
π
```
Now we create another string builder called `msg` which will store the final output.

We iterate `π` over each `i` in the range `β©` `0 328 8`. This is similar to the Python `range()`, using start, stop, and step.
This allows us to take 8 bits as a time from `bits`.

We then perform a pretty complex operation. First, `πͺbits i 8βοΈ` returns a substring from `i` to `i+8` from `bits`. <br/>
Then, `πΊπ’x 2βοΈ` (x being what we just computed) generates an integer in the specified base from the supplied string.
In this case, it reads the binary and converts it into an integer from base 2. Of course, we also have to unwrap this value with `πΊ`<br/>
Finally, `π§x βοΈ` converts the integer into a byte and stores it in `byte`.

The next section is defined as an unsafe block using `β£οΈ`. This is similar to Rust's unsafe as well.<br/>
Inside the unsafe block, we append `byte` to `msg` as a pure byte using `π»πΈπ§ βοΈ`

```
ππ‘msgβοΈ βοΈ
```
Finally, at the very end, all we have to do is convert `msg` from a string builder to a pure string, and print it out using `π βοΈ`.<br />
Because the bytes were appended as raw bytes, they get converted into ascii and thus are printed properly.

## Flag
```bash
>>> emojicodec REALSOLVE.π
>>> ./REALSOLVE
ictf{enc0ding_is_n0t_encrypti0n_1b2e0d43}
```
If you want to run the program yourself without compiling, you have to download both [REALSOLVE](REALSOLVE) and [REALSOLVE.o](REALSOLVE.o)

# Conclusion
Cool basic challenge, and I totally did not learn an esolang to "correctly" solve it.

Thanks for reading!