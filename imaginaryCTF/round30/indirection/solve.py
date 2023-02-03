from PIL import Image

im = Image.open("flag.png")

combine = lambda a,b: (a[0]+b[0], a[1]+b[1])
deltas = [(0,0), (0, 1), (1,0), (1, 1)]

flag = ''
i,j = 0,0
while not flag.endswith("}"):
    data = []
    for delta in deltas:
        px = im.getpixel(combine((i,j), delta))
        data += [px[0]&3, px[1]&3, px[2]&3]
    
    char, x, y = [data[x:x+4] for x in range(0, len(data), 4)]
    char = (char[0]<<6) | (char[1]<<4) | (char[2]<<2) | char[3]
    x = (x[0]<<6) | (x[1]<<4) | (x[2]<<2) | x[3]
    y = (y[0]<<6) | (y[1]<<4) | (y[2]<<2) | y[3]

    flag += chr(char)
    i,j = x,y

print(flag)