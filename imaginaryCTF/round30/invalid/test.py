from Crypto.Util.number import *
from main import Curve, Point
from tqdm import tqdm
# print(lenb'ictf{REDACTED}')

log = 47668570326120565393817310886268521419270938105359688075624396195037899596157
mod = 13519558645540026640388564563515268163402892390877255326302318008910810748754488306996
p   = 115792089237316195423570985008687907853269984665640564039457584007908834671663
a = 0
b = 7

print(p.bit_length())

E = Curve(p, a, b)
G = Point(E, 1, 1)
goal = (66492864269652980102487919283799153077125126114580010532045468163844489036560, 5146098878198351116739696838651916765599566445864102826063619342876788823654)

a = G * log
cap = 2**256 // mod
print(cap.bit_length())

try:
    while True:
        test = long_to_bytes(log)
        if len(test) != 32:
            log += mod
            continue
        try:
            if test.startswith(b'ic'):
                print(test)
            print(test.decode())
            break
        except:
            pass
        log += mod
except KeyboardInterrupt:
    print(log.bit_length(), long_to_bytes(log))
    