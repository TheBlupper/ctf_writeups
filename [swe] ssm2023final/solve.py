import struct
import numpy as np

from itertools import chain
from galois import GF2
from tqdm import tqdm
from pwn import *


def to_double(u):
    buf = struct.pack("<Q", (u >> 12) | 0x3FF0000000000000)
    f64 = struct.unpack("d", buf)[0] - 1
    return f64


def bits_to_f64(bi):
    u = 0
    for i, bit in enumerate(map(int, bi)):
        u |= bit << i
    return to_double(u)


def xor(dst, src, size):
    'Create a matrix that XORs two spans of the state together'
    A = GF2.Identity(128)
    A[dst:dst+size, src:src+size] += GF2.Identity(size)
    return A

# left shift is negative, right shift is positive


def xor_s1_s0(shift):
    'Create a matrix that XORs s1 with a shifted s0'
    if shift > 0:
        return xor(64, shift, 64-shift)
    else:
        return xor(64-shift, 0, 64+shift)


def xor_s1_s1(shift):
    'Create a matrix that XORs s1 with a shifted s1'
    if shift > 0:
        return xor(64, 64+shift, 64-shift)
    else:
        return xor(64-shift, 64, 64+shift)


print('[*] Samlar datapunkter...')
io = process('./service.js')
#io = remote('35.217.53.195', 50000, ssl=True)

points = []
for i in tqdm(range(128)):
    io.sendlineafter(b'[J/n]', b'j')
    io.sendlineafter(b'gissning?\n', b'0.5')
    points += [int('lågt!' in io.recvline().decode())]
# Reverse each chunk to get the chronological PRNG output
chunks = [points[i:i+64][::-1] for i in range(0, len(points), 64)]
points = GF2([*chain(*chunks)])

'''
Construct a matrix that is equivalent to:
    s0, s1 = s1, s0
    s1 ^= (s1 << 23)&MASK
    s1 ^= (s1 >> 17)&MASK
    s1 ^= s0 & MASK
    s1 ^= (s0 >> 26) & MASK
'''

SWAP = np.roll(GF2.Identity(128), 64, axis=1)
XS128 = xor_s1_s0(26)@xor_s1_s0(0)@xor_s1_s1(17)@xor_s1_s1(-23)@SWAP


def extract(i):
    # extracts only the 64th bit and puts it in the ith position
    A = GF2.Zeros((128, 128))
    A[i, 63] = 1
    return A


A = GF2.Zeros((128, 128))
MAT_POW = GF2.Identity(128)
for i in range(128):
    A += extract(i)@MAT_POW
    MAT_POW = XS128 @ MAT_POW

original_state = np.linalg.solve(A, points)
# We add 63 since it will have just filled a new bucket
next_state = np.linalg.matrix_power(XS128, 128+63)@original_state
s0 = next_state[:64]
io.sendlineafter(b'[J/n]', b'j')

guess = bits_to_f64(s0)
io.sendlineafter(b'gissning?\n', str(guess).encode())
print(io.recvline().decode().strip())