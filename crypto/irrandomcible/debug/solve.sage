from tqdm import trange
from ast import literal_eval
proof.all(False)

with open('out.txt', 'r') as file:
    res = literal_eval(file.read())

M = max([
    max(v)
    for block in res
    for v in block
])

R = [
    sum(map(vector, block))
    for block in res
]

print('Loaded!')

i,d,e = b'ide'
a,b,c = R[0][:3]
for p in trange(M+(M&1)+1, 2**32, 2):
    if (i*b % p == d*a % p) and (i*c % p == a*e % p) and is_pseudoprime(p):
        break
k = i * pow(a,-1,p) % p
print('p =', p)
print(bytes(k * R[0] % p))

for B in R[1:]:
    s = pow(B[0], -1, p)
    B = s*B % p
    for w in range(1, 256):
        if all(x < 256 for x in w*B%p):
            print(bytes(w*B%p))
            break
    else:
        print('???')



# n = 7
# Selected random generators!
# gs = [[(1, 5), (2, 4, 6, 3)], [(1, 2, 5), (3, 4)]]
# #G = 720
# p = 193715947