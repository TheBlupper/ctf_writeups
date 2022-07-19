from z3 import *

a = [Int(str(i)) for i in range(24)]
s = Solver()
fs = open('conditions.txt', 'r').readlines()
def popf():
    return (fs.pop(), fs.reverse())[0]

for i in range(1,17):
    bits = f'{i%16:04b}'
    f = popf()
    for b in bits:
        f = f.replace('==', 'EQ' if b=='1' else 'NE', 1)
    f = f.replace('EQ', '==').replace('NE', '!=')
    exec(f)

assert s.check() == sat
m = s.model()
flag = ''.join(chr(m[ch].as_long()) for ch in a)
print(flag)