# Patch deprecation warnings
sage.structure.element.is_Matrix = lambda z: isinstance(z, sage.structure.element.Matrix)
# See README.md of Baby Bundle for this package
from vector_bundle import *
from function_field_elliptic import EllipticFunctionField
from hashlib import sha256
from secret import flag, setup, reduced_bundle
import signal

# setup: don't worry about it, it just prepares the internal machinery of
#        reduced_bundle
#
# reduced_bundle: given [a representant of] an isomorphism class of vector bundles,
#                 returns a canonical representant.
#                 The second parameter is the degree of the vector bundle (can be
#                 expensive to compute).
#
# Knowing the internals of these functions is not necessary to solve the chall.
# They are not given because I couldn't manage to write them without using
# machinery that would give away half of the solve, sorry :c

proof.all(False)
VectorBundle.__mul__ = VectorBundle.tensor_product
VectorBundle.__pow__ = VectorBundle.tensor_power

q = next_prime(7331 + 1337)
a = 901
b = 6442
F = GF(q)
C = EllipticCurve(F, [a, b])
K = EllipticFunctionField(C)
B = K.base_field()
x = B.gen()
y = K.gen()
o = B.maximal_order()
O = K.maximal_order()
Inf, = K.places_infinite()

setup(q, a, b, F, x, y, K, O, Inf)
print('Setup done')


def dump_bundle(E):
    raw = f'{[I.gens() for I in E.coefficient_ideals()]};\
            {E.basis_finite()};{E.basis_infinite()}'
    return raw.replace('^', '**').replace(' ', '')


def parse_bundle(raw):
    parse = lambda s: eval(s, { 'x': x, 'y': y, '__builtins__': None }, {})
    ideals, g_fin, g_inf = raw.split(';')
    ideals = [*map(O.ideal, parse(ideals))]
    g_fin  = matrix(K, parse(g_fin))
    g_inf  = matrix(K, parse(g_inf))
    return VectorBundle(K, ideals, g_fin.T, g_inf.T)


def random_place():
    p = o.ideal(x - F.random_element()).place()
    return choice(K.places_above(p))


def gen_priv_key():
    I = prod(random_place().prime_ideal()**ZZ(randint(-10, 10)) for _ in range(20))
    L = VectorBundle(K, I, K.random_element(), K.random_element())

    D = -Inf * ZZ(L.degree())
    L *= VectorBundle(K, D)
    return reduced_bundle(L, 1)


def group_action(E, L, d):
    E = reduced_bundle(E * L, d)
    M = matrix.random(K, E.rank())
    assert M.is_invertible()
    return E.apply_isomorphism(M)


def shared_secret(ES, d):
    ES = reduced_bundle(ES, d)
    s = dump_bundle(ES).encode()
    return sha256(s).digest()


def timeout(signum, frame):
    print('Timed out!')
    exit(1)

signal.signal(signal.SIGALRM, timeout)


if __name__ == '__main__':
    r,d = 4,1
    E0  = atiyah_bundle(K, r, d)
    LA  = gen_priv_key()
    LB  = gen_priv_key()
    EA  = group_action(E0, LA, d)
    EB  = group_action(E0, LB, d)
    EAB = group_action(EA, LB, d)
    EBA = group_action(EB, LA, d)
    ss  = shared_secret(EAB, d)
    assert ss == shared_secret(EBA, d)

    print('-'*20)
    print(dump_bundle(E0))
    print(dump_bundle(EA))
    print(dump_bundle(EB))

    signal.alarm(5) # Tick tock...

    # This is NOT a pyjail
    raw = input('Give me a representant of the shared iso class:\n')
    allowed = '0123456789,;+-*/[]()xy'
    assert all(x in allowed for x in raw)

    if shared_secret(parse_bundle(raw), 1) == ss:
        print('Well done!', flag)
    else:
        print("You're a FAILURE >:c")
