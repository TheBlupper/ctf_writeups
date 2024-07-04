import matplotlib.pyplot as plt
from sage.all import *
from tqdm import tqdm

import angr, claripy
from pwn import p32, bits

p = angr.Project('./pwnymaps', main_opts={'base_addr': 0})

# speed up zeroing of memory in the start
@p.hook(0x195e, length=0x4b)
def _(st):
    st.memory.store(st.regs.rbp-0x1010, b'\0'*0x1000)

# complexity input, we only use 1 coordinate pair
@p.hook(0x1a1c, length=10)
def _(st):
    st.memory.store(st.regs.rsi, 1, endness='I')

# dont run scanf
@p.hook(0x1a9a, length=10)
def _(_): pass

# make us not fail the checksum-check
@p.hook(0x1e15, length=13)
def _(_): pass

def num_to_vec(n, nbits):
    return [(n>>i)&1 for i in range(nbits)]

def vec_to_num(v):
    return sum((int(b)<<i) for i, b in enumerate(v))

init_st = p.factory.entry_state(add_options=angr.options.unicorn)
sm = p.factory.simulation_manager(init_st)
sm.explore(find=0x1a95) # final check
start = sm.found[0]

def oracle(v):
    u0 = vec_to_num(v[:32])
    u1 = vec_to_num(v[32:])

    st = start.copy()
    st.memory.store(st.regs.rsi, claripy.BVV(u0, 32), endness='I')
    st.memory.store(st.regs.rdx, claripy.BVV(u1, 32), endness='I')
    sm = p.factory.simulation_manager(st)
    sm.explore(find=0x214f)
    st = sm.found[0]
    res = st.solver.eval(st.memory.load(st.regs.rbp - 0x1040, 8))
    return num_to_vec(res, 64)

cols = []
# one of the numbers is restricted to 28 bits
for i in tqdm(range(32+28)):
    v = [0]*(32+28)
    v[i] = 1
    cols.append(vector(GF(2), oracle(v)))
A = matrix(GF(2), cols).transpose()
A.visualize_structure().save('A.png')

n = 0x14f
with open('./pwnymaps', 'rb') as f:
    f.seek(0x4020)
    raw =  f.read(8*n)
    targets = [raw[i:i+8] for i in range(0, len(raw), 8)]

X, Y = [], []
for i, tgt in enumerate(targets):
    t = vector(GF(2), bits(tgt)[::-1])
    sol = A.solve_right(t)
    X.append(vec_to_num(sol[:32]))
    Y.append(vec_to_num(sol[32:]))
plt.scatter(X, Y)
plt.show()