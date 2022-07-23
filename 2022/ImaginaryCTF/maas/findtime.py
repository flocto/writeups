import fakeuuid as fuuid
import uuid
import time

def get_time(uuid: uuid.UUID):
    time_low, time_mid, time_hi_version  = uuid.time_low, uuid.time_mid, uuid.time_hi_version
    res = (time_hi_version << 48) | (time_mid << 32) | time_low
    return res

def compare(uuid1: uuid.UUID, uuid2: uuid.UUID):
    return get_time(uuid1) - get_time(uuid2)

uuidd = "c06495a4-0a4d-11ed-a1e4-161d5e4758ae"
node = int(uuidd.split("-")[-1], 16)
clock_seq = int(uuidd.split("-")[-2], 16)
adminUuid = uuid.UUID("{"+uuidd+"}")

uuiddd = "a"
i = 0
start = 1658000000000000000
end   = 1660000000000000000
m = 0
while start < end:
    m = (start + end) // 2
    uuiddd = fuuid.fakeuuid1(timing=m, node=node, clock_seq=clock_seq)

    i += 1
    if i % 10 == 0:
        print(i, m, uuiddd)

    cmp = compare(adminUuid, uuiddd)
    if cmp > 0:
        start = m + 1
    elif cmp < 0:
        end = m - 1
    else:
        break
        
# print date from time in nanoseconds
print(m)
print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m/1e9)))
print("seed: ", round(m/1e9,2))