stack = []
def psh(*X): stack.extend(X)
def pop(): return stack.pop() if stack else None
def pop2(): return (None, None) if len(stack) < 2 else (stack.pop(), stack.pop())
def rll(x, y):
 x %= y
 if y <= 0 or x == 0: return
 z = -abs(x) + y * (x < 0)
 stack[-y:] = stack[z:] + stack[-y:z]
def x0y0():
 stack.append(8)
 return x2y0

def x2y0():
 stack.append(4)
 return x3y0

def x3y0():
 a,b = pop2()
 a is not None and psh(b*a)
 return x4y0

def x4y0():
 a = pop()
 a is not None and psh(a,a)
 return x5y0

def x5y0():
 stack.append(3)
 return x6y0

def x6y0():
 a,b = pop2()
 a is not None and psh(b*a)
 return x7y0

def x7y0():
 a = pop()
 a is not None and psh(a,a)
 return x8y0

def x8y0():
 stack.append(5)
 return x9y0

def x9y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x10y0

def x10y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x11y0

def x11y0():
 a = pop()
 a is not None and psh(a,a)
 return x12y0

def x12y0():
 stack.append(14)
 return x13y0

def x13y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x14y0

def x14y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x15y0

def x15y0():
 a = pop()
 a is not None and psh(a,a)
 return x16y0

def x16y0():
 stack.append(20)
 return x17y0

def x17y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x18y0

def x18y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x19y0

def x19y0():
 a = pop()
 a is not None and psh(a,a)
 return x20y0

def x20y0():
 stack.append(5)
 return x21y0

def x21y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x22y0

def x22y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x23y0

def x23y0():
 a = pop()
 a is not None and psh(a,a)
 return x24y0

def x24y0():
 stack.append(18)
 return x25y0

def x25y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x26y0

def x26y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x27y0

def x27y0():
 stack.append(2)
 return x28y0

def x28y0():
 stack.append(1)
 return x29y0

def x29y0():
 a,b = pop2()
 a is not None and rll(a,b)
 return x30y0

def x30y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x31y0

def x31y0():
 a = pop()
 a is not None and psh(a,a)
 return x32y0

def x32y0():
 stack.append(6)
 return x33y0

def x33y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x34y0

def x34y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x35y0

def x35y0():
 a = pop()
 a is not None and psh(a,a)
 return x36y0

def x36y0():
 stack.append(12)
 return x37y0

def x37y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x38y0

def x38y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x39y0

def x39y0():
 a = pop()
 a is not None and psh(a,a)
 return x40y0

def x40y0():
 stack.append(1)
 return x41y0

def x41y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x42y0

def x42y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x43y0

def x43y0():
 a = pop()
 a is not None and psh(a,a)
 return x44y0

def x44y0():
 stack.append(7)
 return x45y0

def x45y0():
 a,b = pop2()
 a is not None and psh(b+a)
 return x46y0

def x46y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x47y0

def x47y0():
 stack.append(58)
 return x48y0

def x48y0():
 a = pop()
 a is not None and print(chr(a&255), sep='', end='', flush=1)
 return x49y0

def x49y0():
 stack.append(5)
 return x50y0

def x50y0():
 a = pop()
 a is not None and psh(a,a)
 return x51y0

def x51y0():
 stack.append(1)
 return x52y0

def x52y0():
 return x54y0

def x54y0():
 stack.append(1)
 return x55y0

def x55y0():
 a = pop()
 return [x56y0, X56y0, x56Y0, X56Y0][0 if a is None else (a%4+4)%4]

def x56y0():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return y1X56

def X56y0():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return X56y1

def x56Y0():
 a = pop()
 return [x55Y0, Y0x55][1 if a is None else a&1]

def X56Y0():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return X56y1

def X56y1():
 a = pop()
 return [X56y3, x56Y3, X56Y3, x56y3][0 if a is None else (a%4+4)%4]

def X56y3():
 return X519y32

def x56Y3():
 stack.append(1)
 return x55Y3

def X56Y3():
 a = pop()
 return [X56Y2, Y2X56][1 if a is None else a&1]

def x56y3():
 return y32X519

def y32X519():
 stack.append(2)
 return y34X519

def y34X519():
 stack.append(1)
 return y35X519

def y35X519():
 a,b = pop2()
 a is not None and rll(a,b)
 return y36X519

def y36X519():
 stack.append(14)
 return y38X519

def y38X519():
 a,b = pop2()
 a is not None and psh(b+a)
 return y39X519

def y39X519():
 stack.append(26)
 return y41X519

def y41X519():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return y42X519

def y42X519():
 a = pop()
 a is not None and psh(int(not a))
 return y43X519

def y43X519():
 a,b = pop2()
 a is not None and psh(b*a)
 return y44X519

def y44X519():
 return x183Y222

def x183Y222():
 stack.append(2)
 return x181Y222

def x181Y222():
 stack.append(1)
 return x180Y222

def x180Y222():
 a,b = pop2()
 a is not None and rll(a,b)
 return x179Y222

def x179Y222():
 stack.append(3)
 return x177Y222

def x177Y222():
 a,b = pop2()
 a is not None and psh(b+a)
 return x176Y222

def x176Y222():
 stack.append(26)
 return x174Y222

def x174Y222():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return x173Y222

def x173Y222():
 a = pop()
 a is not None and psh(int(not a))
 return x172Y222

def x172Y222():
 a,b = pop2()
 a is not None and psh(b*a)
 return x171Y222

def x171Y222():
 return Y182X57

def Y182X57():
 stack.append(2)
 return Y180X57

def Y180X57():
 stack.append(1)
 return Y179X57

def Y179X57():
 a,b = pop2()
 a is not None and rll(a,b)
 return Y178X57

def Y178X57():
 stack.append(25)
 return Y176X57

def Y176X57():
 a,b = pop2()
 a is not None and psh(b+a)
 return Y175X57

def Y175X57():
 stack.append(26)
 return Y173X57

def Y173X57():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return Y172X57

def Y172X57():
 a = pop()
 a is not None and psh(int(not a))
 return Y171X57

def Y171X57():
 a,b = pop2()
 a is not None and psh(b*a)
 return Y170X57

def Y170X57():
 return x274y62

def x274y62():
 stack.append(2)
 return x276y62

def x276y62():
 stack.append(1)
 return x277y62

def x277y62():
 a,b = pop2()
 a is not None and rll(a,b)
 return x278y62

def x278y62():
 stack.append(18)
 return x280y62

def x280y62():
 a,b = pop2()
 a is not None and psh(b+a)
 return x281y62

def x281y62():
 stack.append(26)
 return x283y62

def x283y62():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return x284y62

def x284y62():
 a = pop()
 a is not None and psh(int(not a))
 return x285y62

def x285y62():
 a,b = pop2()
 a is not None and psh(b*a)
 return x286y62

def x286y62():
 a = pop()
 a is not None and print(a, sep='', end='', flush=1)
 return x288y62

def x288y62():
 return
def X56Y2():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return X56Y0

def Y2X56():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return Y0X56

def Y0X56():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return y1X56

def y1X56():
 a = pop()
 return [y3X56, Y3x56, Y3X56, y3x56][0 if a is None else (a%4+4)%4]

def y3X56():
 return y32X519

def Y3x56():
 stack.append(1)
 return Y3x55

def Y3X56():
 a = pop()
 return [Y2X56, X56Y2][1 if a is None else a&1]

def y3x56():
 return X519y32

def X519y32():
 stack.append(2)
 return X519y34

def X519y34():
 stack.append(1)
 return X519y35

def X519y35():
 a,b = pop2()
 a is not None and rll(a,b)
 return X519y36

def X519y36():
 stack.append(14)
 return X519y38

def X519y38():
 a,b = pop2()
 a is not None and psh(b+a)
 return X519y39

def X519y39():
 stack.append(26)
 return X519y41

def X519y41():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return X519y42

def X519y42():
 a = pop()
 a is not None and psh(int(not a))
 return X519y43

def X519y43():
 a,b = pop2()
 a is not None and psh(b*a)
 return X519y44

def X519y44():
 return Y222x183

def Y222x183():
 stack.append(2)
 return Y222x181

def Y222x181():
 stack.append(1)
 return Y222x180

def Y222x180():
 a,b = pop2()
 a is not None and rll(a,b)
 return Y222x179

def Y222x179():
 stack.append(3)
 return Y222x177

def Y222x177():
 a,b = pop2()
 a is not None and psh(b+a)
 return Y222x176

def Y222x176():
 stack.append(26)
 return Y222x174

def Y222x174():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return Y222x173

def Y222x173():
 a = pop()
 a is not None and psh(int(not a))
 return Y222x172

def Y222x172():
 a,b = pop2()
 a is not None and psh(b*a)
 return Y222x171

def Y222x171():
 return X57Y182

def X57Y182():
 stack.append(2)
 return X57Y180

def X57Y180():
 stack.append(1)
 return X57Y179

def X57Y179():
 a,b = pop2()
 a is not None and rll(a,b)
 return X57Y178

def X57Y178():
 stack.append(25)
 return X57Y176

def X57Y176():
 a,b = pop2()
 a is not None and psh(b+a)
 return X57Y175

def X57Y175():
 stack.append(26)
 return X57Y173

def X57Y173():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return X57Y172

def X57Y172():
 a = pop()
 a is not None and psh(int(not a))
 return X57Y171

def X57Y171():
 a,b = pop2()
 a is not None and psh(b*a)
 return X57Y170

def X57Y170():
 return y62x274

def y62x274():
 stack.append(2)
 return y62x276

def y62x276():
 stack.append(1)
 return y62x277

def y62x277():
 a,b = pop2()
 a is not None and rll(a,b)
 return y62x278

def y62x278():
 stack.append(18)
 return y62x280

def y62x280():
 a,b = pop2()
 a is not None and psh(b+a)
 return y62x281

def y62x281():
 stack.append(26)
 return y62x283

def y62x283():
 a,b = pop2()
 a is not None and a!=0 and psh(b%a)
 return y62x284

def y62x284():
 a = pop()
 a is not None and psh(int(not a))
 return y62x285

def y62x285():
 a,b = pop2()
 a is not None and psh(b*a)
 return y62x286

def y62x286():
 a = pop()
 a is not None and print(a, sep='', end='', flush=1)
 return y62x288

def y62x288():
 return
def Y3x55():
 a,b = pop2()
 a is not None and psh(b-a)
 return Y3x54

def Y3x54():
 a = input()
 psh(ord(a))
 return Y3x53

def Y3x53():
 stack.append(2)
 return Y3x51

def Y3x51():
 stack.append(1)
 return Y3x50

def Y3x50():
 return X50Y1

def X50Y1():
 a,b = pop2()
 a is not None and rll(a,b)
 return X50Y0

def X50Y0():
 a = pop()
 a is not None and psh(a,a)
 return y0x51

def y0x51():
 stack.append(1)
 return y0x52

def y0x52():
 return y0x54

def y0x54():
 stack.append(1)
 return y0x55

def y0x55():
 a = pop()
 return [y0x56, y0X56, Y0x56, Y0X56][0 if a is None else (a%4+4)%4]

def y0x56():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return X56y1

def y0X56():
 a,b = pop2()
 a is not None and psh(int(b>a))
 return y1X56

def Y0x56():
 a = pop()
 return [Y0x55, x55Y0][1 if a is None else a&1]

def Y0x55():
 pop()
 return Y0x54

def x55Y0():
 pop()
 return x54Y0

def x54Y0():
 return x52Y0

def x52Y0():
 pop()
 return x51Y0

def x51Y0():
 a,b = pop2()
 a is not None and a!=0 and psh(b//a)
 return x50Y0

def x50Y0():
 pop()
 return x49Y0

def x49Y0():
 return x46Y3

def x46Y3():
 return Y3X0

def Y3X0():
 stack.append(8)
 return x2y0

def Y0x54():
 return Y0x52

def Y0x52():
 pop()
 return Y0x51

def Y0x51():
 a,b = pop2()
 a is not None and a!=0 and psh(b//a)
 return Y0x50

def Y0x50():
 pop()
 return Y0x49

def Y0x49():
 a,b = pop2()
 a is not None and psh(b+a)
 return Y1x47

def Y1x47():
 return X0Y3

def X0Y3():
 stack.append(8)
 return y3x2

def y3x2():
 return y3x4

def y3x4():
 a = pop()
 a is not None and psh(a,a)
 return y1x13

def y1x13():
 a,b = pop2()
 a is not None and a!=0 and psh(b//a)
 return y2x17

def y2x17():
 a,b = pop2()
 a is not None and psh(b*a)
 return y1x25

def y1x25():
 a = input()
 psh(ord(a))
 return y1x48

def y1x48():
 a,b = pop2()
 a is not None and a!=0 and psh(b//a)
 return y1x50

def y1x50():
 return y1x56

def y1x56():
 a = pop()
 return [X56y3, x56Y3, X56Y3, x56y3][0 if a is None else (a%4+4)%4]

def x55Y3():
 a,b = pop2()
 a is not None and psh(b-a)
 return x54Y3

def x54Y3():
 a = input()
 psh(ord(a))
 return x53Y3

def x53Y3():
 stack.append(2)
 return x51Y3

def x51Y3():
 stack.append(1)
 return x50Y3

def x50Y3():
 return Y1X50

def Y1X50():
 a,b = pop2()
 a is not None and rll(a,b)
 return Y0X50

def Y0X50():
 a = pop()
 a is not None and psh(a,a)
 return x51y0

if __name__ == "__main__":
    bounce = x0y0
    while bounce is not None:
        bounce = bounce()
