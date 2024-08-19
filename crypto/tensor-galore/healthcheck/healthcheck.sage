#!/usr/bin/env sage

# Patch deprecation warnings
sage.structure.element.is_Matrix = lambda z: isinstance(z, sage.structure.element.Matrix)
# See README.md of Baby Bundle for this package
from vector_bundle import *
from function_field_elliptic import EllipticFunctionField

proof.all(False)
VectorBundle.__mul__ = VectorBundle.tensor_product
VectorBundle.__pow__ = VectorBundle.tensor_power


q = next_prime(7331 + 1337)
a = 901
b = 6442
F = GF(q)
C = EllipticCurve(F, [a, b])
K = EllipticFunctionField(C)
x = K.base_field().gen()
y = K.gen()
O = K.maximal_order()
Inf, = K.places_infinite()


def dump_bundle(E):
    raw = f'{[I.gens() for I in E.coefficient_ideals()]};{E.basis_finite()};{E.basis_infinite()}'
    return raw.replace('^', '**').replace(' ', '')


def parse_bundle(raw):
    ideals, g_fin, g_inf = raw.split(';')
    ideals = [*map(O.ideal, eval(ideals, { 'x': x, 'y': y, '__builtins__': None }, {}))]
    g_fin  = matrix(K, eval(g_fin, { 'x': x, 'y': y, '__builtins__': None }, {}))
    g_inf  = matrix(K, eval(g_inf, { 'x': x, 'y': y, '__builtins__': None }, {}))
    return VectorBundle(K, ideals, g_fin.T, g_inf.T)


Fe = GF(q**12 , 'a')
Ce = EllipticCurve(Fe, [a, b])
Ke = EllipticFunctionField(Ce)
xe = Ke.base_field().gen()
ye = Ke.gen()
Oe = Ke.maximal_order()

_f = K.base_field().hom([xe])
f  = K.hom([ye], _f)
Ke.base_field().register_coercion(_f)
Ke.register_coercion(f)


def bundle_from_point(P, r, d):
    P = O.ideal(x - P.x(), y - P.y()).place()
    L = VectorBundle(K, Inf - P)
    return atiyah_bundle(K, r, d, L)


def point_from_bundle(E, d):
    # d: degree of E
    L = E.determinant()
    D = L.coefficient_ideals()[0].divisor()
    P = Ce(0)
    for p, m in D.list():
        Ie = p.prime_ideal() * Oe
        for pe, _ in Ie.divisor().list():
            X, Y = pe.prime_ideal().gens()
            P += m * Ce(xe-X, ye-Y)

    if d < 0:
        P = -P
    h = gcd(E.rank(), d)
    return P.change_ring(F).division_points(h)[0]


from os import environ
environ['NO_COLOR'] = '1'
from pwn import process, remote, context
context.log_level = 'debug'

def solve():
    def handle_pow(r):
        print(io.recvuntil(b'python3 '))
        print(r.recvuntil(b' solve '))
        challenge = r.recvline().decode('ascii').strip()
        p = process(['kctf_bypass_pow', challenge])
        solution = p.readall().strip()
        r.sendline(solution)
        print(r.recvuntil(b'Correct\n'))

    io = remote('localhost', 1337)

    print(io.recvuntil(b'== proof-of-work: '))
    if io.recvline().startswith(b'enabled'):
        handle_pow(io)

    # io = process(['sage', 'server.sage'])
    io.recvuntil(b'-'*20 + b'\n')

    E0, EA, EB = [
        parse_bundle(io.recvline(False).decode())
        for _ in range(3)
    ]

    r,d = 4,1
    P = point_from_bundle(E0, d)
    Q = point_from_bundle(EA, d)

    RA  = (Q-P).division_points(r)[0]
    LA  = bundle_from_point(RA, 1, 0) # myLA^r ~= LA^r
    EBA = EB * LA                     # myEBA  ~= EBA

    io.sendlineafter(b'class:\n', dump_bundle(EBA).encode())
    ree = io.recvline(False)
    print(ree, b'idek{' in ree)
    if b'idek{' in ree:
        exit(int(0))

for _ in range(3):
    try:
        solve()
    except EOFError:
        pass
exit(int(1))
