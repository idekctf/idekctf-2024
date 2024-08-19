from random import shuffle
from tqdm import tqdm, trange
proof.all(False)

flag = b'idek{5um_0f_1rr3p_15_d14g0n4l}'

n  = randint(5, 10)
print('n =', n)
Sn = SymmetricGroup(n)
gs = [Sn.random_element() for _ in range(randint(1, 3))]
print('Selected random generators!')
print('gs =', gs)

G = PermutationGroup(gs)
n = G.cardinality()
print('#G =', n)

p = random_prime(2**32, lbound=127)
F = GF(p)
print('p =', p)

irr = gap.IrreducibleRepresentations(G)
rep = irr[randint(2, int(irr.Length()))]
print('Generated rep!')
print(rep)


G = rep.Image()
reps = [
    matrix(F,r)
    for r in tqdm(G.Enumerator())
    if r != G.One() # It would be too easy :)
]
print('Computed image of G!')


n = int(G.One().Length())
flag += bytes( (n - len(flag)) % n )


res = []
for i in trange(0, len(flag), n):
    λ = F.random_element()
    v = λ * vector(F, flag[i:i+n])
    res.append([
        tuple(r*v)
        for r in reps
        if  not r.is_one()
    ])
    shuffle(res[-1])
print('Computed image of flag!')

with open('out.txt', 'w') as file:
    file.write(str(res))
