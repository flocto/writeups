import os
from random import randint
from itertools import chain
from tqdm import tqdm

from PIL import Image

get_bits = lambda n: [int(i) for i in '{:08b}'.format(n)]

path = 'flag.png'
for secret in tqdm(range(237)): #237 gives original image, 255 gives flag
    with Image.open(path) as image:
        dim = width, height = image.size
        with Image.new(image.mode, dim) as canvas:
            for x in range(width):
                for y in range(height):
                    nx = (2 * x + y) % width
                    ny = (1 * x + y) % height
                    px = list(image.getpixel((nx, height-ny-1)))
                    canvas.putpixel((x, height-y-1), tuple(px))
    # os.remove(path)
    secret += 1
    path = 'reversed.png'
    canvas.save(path)
    
    #extract data
    if (secret == 254):
        binary = ""
        done = False
        count = 0
        with Image.open(path) as image:
            dim = width, height = image.size
            for x in range(width):
                for y in range(height):
                    nx = (2 * x + y) % width
                    ny = (1 * x + y) % height
                    px = list(image.getpixel((nx, height-ny-1)))
                    
                    if (not done): binary += str(get_bits(px[2])[7])
                    count += 1
                    if (count % 8 == 0): binary += " "

        binary = binary.split(" ")
        start = ""
        for y in binary:
            if y != '': start += chr(int(y, 2))
        print(start[:50])