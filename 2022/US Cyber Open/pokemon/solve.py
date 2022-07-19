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
from collections import Counter
print(Counter(msg))
# Counter({'n': 1246, 'b': 1055, 'u': 997, 'y': 853, 'a': 784, 'd': 757, 'r': 644, 'l': 623, 'o': 550, 'q': 467, 's': 435, 'm': 363, 'w': 342, 'f': 337, 'p': 287, 'c': 278, 'i': 269, 'k': 268, 'z': 253, 'h': 185, 't': 154, 'x': 62, 'j': 31, 'e': 12, 'v': 9, 'g': 3})

# monosubstitution cipher
# ends up being script for first episode of pokemon LOL
# followed by flag is ucsg{itsunown}
