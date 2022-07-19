# Pokemon
>We've intercepted an encrypted message, can you decrypt it? Flag Submission format: uscg{[a-z]+}

First blood! And cool image techniques.

## First look
We are given a single image to start with:
![Lots and lots of unowns](ciphertext.png)
Wow.

At first, the provided image looks huge. It measures at 5456 by 7936 pixels, and even causes the engine I'm using to preview this markdown to lag.
Zooming in, we see that the images contains a lot of [Unowns.](https://bulbapedia.bulbagarden.net/wiki/Unown_(Pok%C3%A9mon))

As Unowns represent a single letter each, the goal of this challenge is probably to convert each one into a letter and find the flag
in the resulting message.

## Splitting the image
Our first task is then to isolate each individual Unown. I assumed each picture is probably square, so the dimensions must be a common
factor of 5456 and 7936. 

Calculating these common factors, we get `1, 2, 4, 8, 16, 31, 62, 124, 248, 496`. Obviously 1, 2, 4, 8, and 16 are too small, and 124, 248, 496
seem too big. This means it was between 31 and 62 to be the image size. 

I ended up writing up a script to take the first n x n pixels of the image.
```python
from PIL import Image

img = Image.open('ciphertext.png')
N = 62
sqr = (0, 0, N, N)
tile = img.crop(sqr)
img.save("char.png")
```
Trying out both 62 and 31, we see that 62 works, generating the first Unown.

![Unown of the character N](n.png)

# Image hashing
Well, now that we have the dimensions of each character, we can easily split the image. However, how do we actually convert the each character into
letters?

The solution: Perceptual image hashing

Perceptual image hashing allows us to hash the 'appearance' of an image, rather than its pure data. For example, if one of the Unowns was slightly discolored,
but still had the same shape, a perceptual image hash would hash it to a value quite similar to that of a normal character.

Applying this to our code, we can hash every tile, and if the tile is one that hasn't been seen before, then we can mark it as a new letter and save the tile
seperately.

Afterwards, I went and manually edited the name of each file to its matching letter, but it turns out that won't be necessary.

## Parsing the message
Now we can finally start translating the characters to text. We just make sure to keep track of any image hashes, and write out the output once its finished
(Remember, there are a lot of letters still.)
```python
from PIL import Image
from itertools import product
import imagehash

img = Image.open('ciphertext.png')
print(img.size)
WIDTH, HEIGHT = img.size
TILE_SIZE = 62
COLS = WIDTH // TILE_SIZE
ROWS = HEIGHT // TILE_SIZE

grid = product(range(0, ROWS), range(0, COLS))

hashes = {}
for letter in "abcdefghijklmnopqrstuvwxyz":
    hash = imagehash.phash(Image.open(f'{letter}.png'))
    hashes[hash] = letter



msg = ""
lasti = 0
for i, j in grid:
    i *= TILE_SIZE
    j *= TILE_SIZE
    tile = (j, i, j + TILE_SIZE, i + TILE_SIZE)
    tile = img.crop(tile)
    hash = imagehash.phash(tile)
    if lasti != i:
        # msg += "\n"
        pass
    msg += hashes[hash]
    lasti = i

with open('message.txt', 'w') as f:
    f.write(msg)
```
However, even though our translation was successful, our text still looks like garbage.
```
ydmdamboadbhncadrulnhyuuqnzaulylbodyuuyikblhsucndcyohbsdinroacluhyikydmulnonauarulnlfpdbrarpbznobtcndcyoularibsqmhnulnndmbtdamboadbzyauulnuoyadnooniyqqrdamboadbzlailpbknwbdzaqqlnsrndbzblaurbdaeydmdbzularcaydupbknwbdrbdulnyuuyikblhsucndcyojswpryramncndcyoarwbxadchnysuatsqqfubmyfauruoyadadcarubpdbuildbmbshuyhbsuaufnraywyrlyrlknuilswaryhbftobwpyqqnuubzdydmdbzulyuawun...(truncated)
```

## Actual crypto
Hmmm... Given that this is a crypto challenge, there must be something else going on here.
```python
from collections import Counter
print(Counter(msg))
# Counter({'n': 1246, 'b': 1055, 'u': 997, 'y': 853, 'a': 784, 'd': 757, 'r': 644, 'l': 623, 'o': 550, 'q': 467, 's': 435, 'm': 363, 'w': 342, 'f': 337, 'p': 287, 'c': 278, 'i': 269, 'k': 268, 'z': 253, 'h': 185, 't': 154, 'x': 62, 'j': 31, 'e': 12, 'v': 9, 'g': 3})
```
Aha! The character frequencies are not uniform, hinting at something like mono-substitution.

Running our message through a simple mono-substitution solver, we get output that seems to be the script to the first episode of Pokémon:
```
ANDNIDORINOBEGINSTHEBATTLEWITHAHORNATTACKOHBUTGENGARBOUNCESRIGHTBACKANDTHEREITISTHEHYVNOSISVOWEROFGENGARTHISCOULDBETHEENDOFNIDORINOWAITTHETRAINERRECALLSNIDORINOWHICHVOKEPONWILLHEUSENOWOHITSONIJANDNOWTHISGIANTVOKEPONSONTHEATTACKOHBUTGENGARMUPVSASIDEGENGARISPOXINGBEAUTIFULLYTODAYITSTRAININGISTOVNOTCHNODOUBTABOUTITYESIAPASHASHKETCHUPISABOYFROPVALLETTOWNANDNOWTHATIPTE...(truncated)
```
Now the output has to be correct.
We can also find our flag at the end of the message.
```
...theflagisuscgitsunown
uscg{itsunown}
```
---

Overall, this challenge was really fun, glad I got to reuse perceptual image hashing after learning about it during PlaidCTF.
Also was nice getting first blood, I think this might actually be my first first blood! :yum: