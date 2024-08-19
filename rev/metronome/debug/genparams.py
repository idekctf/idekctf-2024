import random

random.seed(0x69420133733102496)

with open('flag.txt', 'rb') as f:
    flag = f.readline().strip()

print(flag)

#

n = len(flag)
nbit = 8 * n

def flag_bit(x):
    flag_int = int.from_bytes(flag, byteorder='little')
    return (flag_int >> x) & 1

print([flag_bit(i) for i in range(nbit)])

#

edg = []

for i in range(1, nbit):
    edg.append((random.randrange(0, i), i))

edg.append((random.randrange(0, n), random.randrange(0, n)))

random.shuffle(edg)

#

k = 3524578 + 2 * 2178309 + 1346269

edgv = []
for e in edg:
    ex, ey = flag_bit(e[0]), flag_bit(e[1])
    edgv.append(2 if ex != ey else k if ex == 1 else 0.25)

print(edgv)

#

bnd = []
for i in range(nbit):
    for j in range(nbit):
        x, y = edgv[i], edgv[j]
        if x != k and y != k:
            z = x * y
            lb = random.uniform(max(0, z - 2), max(0, z - 0.5))
            ub = random.uniform(z + 1, z + 2)
        elif x == 2 or y == 2:
            lb = random.uniform(32, 64)
            ub = random.uniform(2 * k, 3 * k)
        elif x == y:
            lb = random.uniform(1000, 1024)
            ub = random.uniform(k * k, 3 * k * k)
        else:
            lb = 0
            ub = random.uniform(3 * k // 2, k)

        bnd.append((lb, ub))

#

with open('params.txt', 'w') as f:
    f.write('\n'.join([
        str(n), 
        '{' + ', '.join('{{{}, {}}}'.format(i[0], i[1]) for i in edg) + '}', 
        '{' + ', '.join('{{{:0.2f}, {:0.2f}}}'.format(i[0], i[1]) for i in bnd) + '}'
    ]))
