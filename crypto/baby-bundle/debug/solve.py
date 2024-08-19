from string import printable

out = [49, 52, 55, 58, 62, 66, 71, 76, 81, 86, 431, 444, 457, 470, 484, 498, 512, 526, 540, 554, 568, 582, 596, 610, 625, 640, 655, 670, 685, 700, 715, 730, 745, 760, 775, 790, 134, 141, 148, 155, 162, 169, 176, 184, 192, 200, 208, 216, 224, 232, 240, 248, 257, 266, 275, 284, 293, 303, 313, 323, 333, 345, 24, 25, 26, 27, 28, 29, 31, 33, 35, 37, 39, 41, 43, 45, 47, 91, 96, 101, 106, 113, 120, 127, 357, 369, 381, 393, 405, 418, 805, 820, 835, 850, 23, 0, 1, 4, 2, 3]
enc = bytes.fromhex('5f0a8761f98748422d97f60f11d8590d56e1462409a677fbf52259b084b8a724')

h0_V = { ord(m):d for m,d in zip(printable, out) }

# In Pⁿ, we have h⁰(O(m)) = (m choose m+n) whenever m ≥ 0, and 0 otherwise
#       ~> for n = 1,     = m+1

alpha = sorted(printable.encode())
pwd   = []
for m,n in zip(alpha, alpha[1:]):
    if h0_V[m] + (n-m)*len(pwd) != h0_V[n]:
        # new char discovered!
        # amount of occurences (keeping track of the dims of h⁰ we already know)
        r = h0_V[n] - h0_V[m] - (n-m)*len(pwd)
        print('-'*10)
        print('m  =', bytes([m]))
        print('n  =', bytes([n]))
        print('hm =', h0_V[m])
        print('hn =', h0_V[n])
        print('r  =', r)
        pwd.extend([n]*r)

print(bytes(pwd))

from Crypto.Cipher import AES
from hashlib import sha256

key = sha256(bytes(sorted(pwd))).digest()[:16]
aes = AES.new(key, AES.MODE_ECB)
dec = aes.decrypt(enc)
print('dec:', dec)