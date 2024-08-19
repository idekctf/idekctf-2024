from sage.all import *
from hashlib import shake_256
import random

F2 = GF(2)
n = 4800
ku = 1484
kv = 916
assert (2 * ku - kv <= n//2)

Hu = random_matrix(F2, n//2 - ku, n//2, implementation = "m4ri")
Hv = random_matrix(F2, n//2 - kv, n//2, implementation = "m4ri")
Hs = block_matrix(F2, [
                 [Hu, 0],
                 [Hv, Hv]])

while (S := random_matrix(F2, n//2, n//2, implementation = "m4ri")):
    if S.is_invertible():
        break

perm = list(range(n))
random.shuffle(perm)
P = Matrix(F2, [[1 if i == perm[j] else 0 for j in range(n)] for i in range(n)], implementation = "m4ri")
Hpub = S * Hs * P

def verify(Hpub, msg, e):
    e = vector(F2, e)
    if e.hamming_weight() != kv:
        return False
    n = Hpub.ncols()
    s = shake_256(msg).digest(n//16)
    s = vector(F2, list(map(int, bin(int.from_bytes(s, 'big'))[2:].zfill(n//2))))
    return Hpub * e == s

while 1:
    choice = input("choice: ")
    if 'sign' in choice:
        print("Not implemented yet :)")
    elif 'pkey' in choice:
        data = bytes(dumps(Hpub)).hex()
        print(data)
    elif 'verify' in choice:
        msg = input("msg: ").strip().encode()
        e = input("e: ").strip()[1:-1]
        e = list(map(int, e.split(", ")))
        if verify(Hpub, msg, e):
            print("Valid signature!")
            if msg == b"gimme the flag!":
                with open('flag.txt', 'r') as f:
                    print(f.read())
                    break
    else:
        print("See ya!")
        break
