# Patch deprecation warnings
sage.structure.element.is_Matrix = lambda z: isinstance(z, sage.structure.element.Matrix)
# See README.md for this package
from vector_bundle import *
from string import printable
from tqdm import tqdm

password = ''.join(choice(printable) for _ in range(15)).encode()

p = 66036476783091383193200018291948785097
F = GF(p)
K.<x> = FunctionField(F)
L = VectorBundle(K, -x.zeros()[0].divisor()) # L = O(-1)

V = L.tensor_power(password[0])
for b in tqdm(password[1:]):
    V = V.direct_sum(L.tensor_power(b))

L = L.dual() # L = O(1)
out = [
    len(V.tensor_product(L.tensor_power(m)).h0())
    for m in tqdm(printable.encode())
]

print(out)


from Crypto.Cipher import AES
from hashlib import sha256
from flag import flag
flag += bytes((16-len(flag)) % 16)

key = sha256(bytes(sorted(password))).digest()[:16]
aes = AES.new(key, AES.MODE_ECB)
enc = aes.encrypt(flag)
print('enc:', enc.hex())
