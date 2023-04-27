import json
from struct import unpack
from sage.all import *

N = 0x50d
# The json is a list of rows with the terms
# of each function, we need them as columns
# so we transpose it
A = matrix(json.load(open('coeffs.json'))).transpose()
assert A.nrows() == A.ncols() == N

# Extracted offset of needed array from Binja
f = open('moon', 'rb')
f.seek(0x1fa8060)
needed = vector(unpack('Q'*N, f.read(8*N)))

ans = A.solve_right(needed)
print(''.join(map(chr, ans)))