import random
from pwn import xor
inplen = 29
a1 = b'{\xfa^_y\xc3\xf9FG;\x89;\x05CA\xe2\x11\xa0\xcdd\xfb\xa92v\xb8\xb1\x01\xaf\x85'
s = 'debdbeef_or_sth'
random.seed(s)
random.seed(random.randbytes(inplen))
print(xor(random.randbytes(inplen), a1))