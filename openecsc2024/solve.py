from pwn import *
from sage.all import *
from Crypto.Util.number import bytes_to_long as btl

load('https://raw.githubusercontent.com/TheBlupper/linineq/main/linineq.py')

p = 0xffffffffffffffffffffffffffffffff7fffffff
N = p.bit_length()//8
F = GF(p)
a = F(0xffffffffffffffffffffffffffffffff7ffffffc)
b = F(0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45)
n = 0x0100000000000000000001f4c8f927aed3ca752257
E = EllipticCurve(F, (a, b))
G = E(0x4a96b5688ef573284664698968c38bb913cbfc82, 0x23a628553168947d59dcc912042351377ac5fb32)
E.set_order(n)

d = F(1)
while d.is_square():
    d += 1

nt = 0xfffffffffffffffffffe0b3706d8512b358adda9
ET = E.quadratic_twist(d)
ET.set_order(nt)
GT = ET.gens()[0]

def pad(pwd):
    if len(pwd) % N != 0:
        pad_length = N - (len(pwd) % N)
        pwd += b"\x80"
        pwd += b"\x00"*(pad_length-1)
    return pwd

def is_twist(k):
    try: E.lift_x(ZZ(btl(k)))
    except ValueError: return True
    return False

nsamples = 17

# set this to True if you want
# to calculate the basis yourself
if False:
    from tqdm import tqdm
    pb = tqdm()
    basis = []
    basis_strs = []

    # speed up scalar multiplication slightly
    pows = [2**i * G for i in range(ZZ(n).nbits())]
    while len(basis) < nsamples:
        pb.update()
        k = randrange(n-1)
        # P = k*G
        P = sum(P for i, P in enumerate(pows) if (k>>i)&1)
        x = P.xy()[0]
        s = int(x).to_bytes(N, 'big')

        try: s.decode()
        except ValueError: continue

        # happens ~50% of them time
        if E.lift_x(x) != P: continue
        print(len(basis))
        basis.append(k)
        basis_strs.append(s)
    save((basis, basis_strs), 'basis17.sobj')
else:
    basis, basis_strs = load('basis17.sobj')

# not important
username = b'abc'

with remote('invention.challs.open.ecsc2024.it', 38011) as io:
    k1 = int(io.recvregex(br'k1 = ([0-9]+)\n', capture=True).group(1))
    k2 = int(io.recvregex(br'k2 = ([0-9]+)\n', capture=True).group(1))

    io.sendlineafter(b'Username: ', username)
    io.recvuntil(b'starts with ')
    token = io.recvline().strip()

    first_pwd = token + b'\0'*N + b''.join(basis_strs)
    io.sendlineafter(b'Password: ', first_pwd.hex().encode())

    admin_password = bytes.fromhex(io.recvregex(
        br"Registered user 'admin' with token '[a-zA-Z]*' and password '([a-f0-9]*)'",
        capture=True).group(1).decode())

    admin_pad = pad(admin_password)
    admin_blks = [admin_pad[i:i+N] for i in range(0, len(admin_pad), N)]

    # admin blocks which are on E
    admin_E = [blk for blk in admin_blks[2:] if not is_twist(blk)]

    # admin blocks which are on ET
    admin_ET = [blk for blk in admin_blks[2:] if is_twist(blk)]
    
    M = matrix([basis])
    sol = solve_bounded_mod(M,
        vector([(btl(admin_blks[0])-btl(token))*k1]), # target
        [0]*nsamples, # lb
        [1000]*nsamples, # ub
        n, # mod
    )

    pwd = token + admin_password[N:2*N]
    pwd += b''.join(admin_ET)
    # now Ci will be (0 : 1 : 0) and CTi will be the same as the admin's

    pwd += b''.join(c*s for c, s in zip(sol, basis_strs))
    # now Ci will be equal to admin_blks[0]*Pu

    pwd += b''.join(admin_E)
    # now everything should match

    print(f'{len(pwd) = }')
    io.sendlineafter(b'Username: ', username)
    io.sendlineafter(b'Password: ', pwd.hex().encode())
    io.interactive()