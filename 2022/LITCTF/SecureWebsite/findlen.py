import requests
import time
# adapted from astro's code b/c too lazy to rewrite mine
def findMax():
    url='http://litctf.live:31776/verify?password='
    maxes = []
    curMax = (0,)
    for i in range(1,20):
        payload = url + ("123123123123," * i)[:-1] # 8272582 is '1' encrypted in the RSA
        then = time.time()
        r = requests.get(payload, allow_redirects=False)
        now = time.time()
        delta = now - then
        if delta > curMax[0]:
            curMax = (delta, i)
            # print("New current max: ")
        # print(delta, i, payload)
        maxes.append((delta, i))

    maxes.sort()
    # print(maxes[::-1])
    # print(curMax)
    return maxes[::-1]

ranks = {i:[] for i in range(1,20)}
for i in range(10):
    print("Round", i)
    ranking = findMax()
    for place, (delta, num) in enumerate(ranking):
        print(place, delta, num)
        ranks[num].append(place)
        print(ranks[num])
for i in range(1, 20):
    print(i, ranks[i])
    print("Average:", sum(ranks[i]) / len(ranks[i]))
    print()