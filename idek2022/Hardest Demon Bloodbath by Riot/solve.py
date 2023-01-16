import xml.etree.ElementTree as ET
import zlib
import matplotlib.pyplot as plt
from pwn import xor
from base64 import b64decode
from z3 import *

PLOT_FN = 'plot.png'

# Block types
MOVE_TRIGGER = '901'
COLLISION_BLOCK = '1816'

# Block properties
ID = '1'
X = '2'
Y = '3'
GROUPS = '57'
BLOCKID = '80'
MOVE_TARGET = '51'


def unpack(raw: bytes):
    '''base64.b64decode + zlib.decompress'''
    return zlib.decompress(b64decode(raw, altchars=b'-_')[10:], -zlib.MAX_WBITS).decode()


raw = open('CCLocalLevels.dat', 'rb').read()
lvl_xml_str = unpack(xor(raw, 11))
root = ET.fromstring(lvl_xml_str)
for el in root[0][1]:
    if el.tag != 'd':
        continue
    name = el[3]
    assert name.tag == 's'
    # Find the correct level
    if name.tag != 's' or name.text != 'CTFCHALL2023':
        continue
    lvl_str = unpack(el[5].text+'==')
    break
else:
    print('Could not find the correct level!')
    exit()


def parse_obj(obj_str: str):
    spl = obj_str.rstrip(',').split(',')
    if len(spl) % 2 != 0:
        return {}
    obj = {spl[i]: spl[i+1] for i in range(0, len(spl), 2)}
    # All objects we care about have these
    if not all(k in obj for k in [X, Y, ID, GROUPS]):
        return {}

    obj[X] = float(obj[X])
    # Everything (ish) is on a grid of 30,
    # this makes things easier later
    obj[Y] = float(obj[Y])//30
    obj[GROUPS] = set(map(int, obj[GROUPS].split('.')))
    return obj


# Filter any empty objects
lvl_objs = [*filter(bool, (parse_obj(obj_str)
                    for obj_str in lvl_str.split(';')))]


moves = []
ones = []
twos = []
last = None
for obj in lvl_objs:
    if obj[ID] == COLLISION_BLOCK:
        if obj[BLOCKID] == '3':  # Special :O
            last = obj
        elif obj[BLOCKID] == '2':  # The blocks in the initial column
            twos.append(obj)
        elif obj[BLOCKID] == '1':  # The blocks scattered everywhere
            ones.append(obj)
    elif obj[ID] == MOVE_TRIGGER:
        moves.append(obj)


def getx(o): return o[X]
def gety(o): return o[Y]


ones = sorted(ones, key=getx)
twos = sorted(twos, key=gety)
print(twos[-1][Y]//2)

print('Generating scatter plot...')
plt.scatter(
    [*map(getx, moves)], [*map(gety, moves)],
    s=1, color='purple')
plt.scatter([*map(getx, ones)], [*map(gety, ones)],
            s=1, color='blue')
plt.scatter([*map(getx, twos)], [*map(gety, twos)],
            s=1, color='red')
plt.scatter([getx(last)], [gety(last)],
            s=20, color='green')
# Line indicating end of inputs
plt.plot(
    [getx(twos[0]), getx(last)], [256*2, 256*2],
    linestyle='dashed',
    color='gray')
plt.savefig(PLOT_FN)
print(f'Saved plot to {PLOT_FN}')


input_vars = [Bool(str(i)) for i in range(256)]


def find_assertions(curr):
    '''Return a Z3 expression for when this block is triggered'''
    try:
        two = next(t for t in reversed(twos) if t[Y] == curr[Y])
        should_trigger = False
    except StopIteration:
        two = next(t for t in reversed(twos) if t[Y]+1 == curr[Y])
        should_trigger = True

    two_id = [*(two[GROUPS]-{265, 1001})][0]
    if two_id < 266:  # Input
        return input_vars[two_id-9] if should_trigger else Not(input_vars[two_id-9])

    # Corresponding move-trigger
    m = next(m for m in moves if int(m[MOVE_TARGET]) == two_id)

    # its -1.0 or 0.0, -1.0 meaning it currently wont trigger when ran over
    should_trigger = should_trigger if m[Y] == -1.0 else not should_trigger
    asserts = [find_assertions(one) for one in ones if one[X] == m[X]]
    expr = Or(*asserts)
    if not should_trigger:
        expr = Not(expr)
    return expr


s = Solver()
s.add(find_assertions(last))
print('Z3 go!!!')
assert s.check() == sat
m = s.model()
out = []
# Chunks of 8
for chunk in zip(*[iter(input_vars)]*8):
    # 8 bools to an int
    out.append(sum(2**i for i, v in enumerate(chunk[::-1]) if m[v]))
print('idek{'+bytes(out).decode()+'}')
