def getDelta(a: int, b: int):
    return (a ^ b).bit_count()


for i in range(1000):
    print(i)
    edges = []
    A = i
    for j in range(10):
        B = A + (2 ** j)
        # print(A, B)
        if B < 1000:
            delta = getDelta(A, B)
            cur = edges
            if delta == 1:
                edges.append(B)
            edges = cur
        B = A - (2 ** j)
        # print(A, B)
        if B > 0:
            delta = getDelta(A, B)
            cur = edges
            if delta == 1:
                edges.append(B)
            edges = cur
    with open("egg.txt", "a") as f:
        f.write(str(edges))
        f.write("\n")