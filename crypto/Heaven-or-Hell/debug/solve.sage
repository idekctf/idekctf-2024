from os import environ
environ['NO_COLOR'] = '1'
from pwn import *
import itertools

"""
	CSIDH stuffs
"""

primes = list(prime_range(3,117))
p = 4 * prod(primes) - 1
base = bytes((int(p).bit_length() + 7) // 8)
Fp = GF(p)

def from_weierstrass(EC):
	a, b = EC.a4(), EC.a6()
	F = EC.base_field()
	PR = PolynomialRing(F, name="z")
	z = PR.gens()[0]
	roots = (z**3 + a*z + b).roots()
	assert len(roots) > 0
	alpha = roots[0][0]
	s = (3*alpha**2 + a).sqrt() ** (-1)
	return -3 * (-1)**s.is_square() * alpha * s

def to_weierstrass(A):
	while True:
		B = Fp.random_element()
		if B.is_square() and B != 0:
			break
	a = (3 - A**2) * pow(3 * B**2, -1, p)
	b = (2 * A**3 - 9 * A) * pow(27 * B**3, -1, p)
	return EllipticCurve(Fp, [a, b])

"""
	Generatre a random EC which is deg-isogeny of the given curve A 
"""

def gen(A, deg):
	x = Fp(randint(1, p - 1))
	r = Fp(x**3 + A * x**2 + x)
	s = kronecker_symbol(r, p)
	EC = to_weierstrass(A)
	if s == -1:
		EC = EC.quadratic_twist()
	while True:
		tmp = EC.random_element()
		if not tmp.is_zero():
			break
	assert (p + 1) % deg == 0
	R = ((p + 1) // deg) * tmp
	phi = EC.isogeny(R)
	EC = phi.codomain()
	if s == -1:
		EC = EC.quadratic_twist()
	return phi, from_weierstrass(EC)

def handle_pow(r):
	print(r.recvuntil(b'python3 '))
	print(r.recvuntil(b' solve '))
	challenge = r.recvline().decode('ascii').strip()
	p = process(['kctf_bypass_pow', challenge])
	solution = p.readall().strip()
	r.sendline(solution)
	print(r.recvuntil(b'Correct\n'))

def conn():

	r = remote('localhost', int(1337))

	print(r.recvuntil(b'== proof-of-work: '))
	if r.recvline().startswith(b'enabled'):
		handle_pow(r)

	return r
	# if __debug__:
	# 	return process(["sage", "./server.sage"])
	# else:
	# 	exit()


def solve(server):
	A = int(server.recvline().split()[-1])
	D = int(server.recvline().split()[-1])

	server.sendlineafter(b"Deal with [A]ngel or [D]evil? Make your choice carefully: ", b"D")

	def query(server, coef):
		server.sendlineafter(b"Enter the montgomery coefficient: ", str(coef).encode())
		return int(server.recvline()) 

	"""
		Generate random EC that is 4-isogeny of previous one and get truncated coefficients
	"""

	vals = [query(server, A)]
	for _ in range(3):
		while True:
			phi, _A = gen(A, 4)
			if _A not in Fp:
				continue
			if _A != A:
				break
		vals.append(query(server, _A))
		A = _A

	P.<a, b, c, d> = PolynomialRing(GF(p)) 
	vars = P.gens()
	coef = [vals[i] + vars[i] for i in range(4)]

	"""
		Guess the right relation between coefficients of 4-isogenies
	"""

	eq1 = lambda A, B : B * (A + 2) - 2 * (A - 6)
	eq2 = lambda A, C : C * (2 - A) - 2 * (A + 6)

	for ch in itertools.product([0, 1], repeat = 3):
	
		pols = [eq1(coef[i], coef[i+1]) if ch[i] else eq2(coef[i], coef[i+1]) for i in range(3)]

		"""
			Construct lattice for hunting the small roots of these polynomial equations 
		"""

		A, mons = Sequence(pols).coefficient_matrix()
		A = A.change_ring(ZZ).T.dense_matrix()
		consts = A.rows()[-1]

		"""
			The roots are expected to have bit lengths = (int(p.nbits()) * 0.3) = 46
		"""

		target = [2**(46 * (__[0].total_degree())) for __ in mons[:-1]]

		A = Matrix(A.rows()[:-1]).dense_matrix()
		M = block_matrix(ZZ, [
			[A, 1, 0],
			[p, 0, 0],
			[Matrix(consts), -Matrix([target]), Matrix([1])]]
		)

		bit_sizes = [1] * 3 + target + [1]
		W = diagonal_matrix([max(bit_sizes) // bit_size for bit_size in bit_sizes])

		M *= W
		M = M.LLL()
		M /= W

		for row in M:
			row *= row[-1]
			if row[-1] != 1: # Check whether the last row is multiplied by +-1
				continue

			"""
				mons = [a * b, b * c, c * d, a, b, c, d]
			"""

			recovered_mons = [r + t for r, t in zip(row[3:-1], target)]
			recovered_vars = recovered_mons[-4:]

			if [recovered_vars[i] * recovered_vars[i+1] for i in range(3)] == recovered_mons[:3]:
				sec = ZZ(vals[0] + recovered_vars[0])
				server.sendlineafter(b'Did Angel or Devil tell your the secret: ', str(sec))
				flag = server.recvline()
				if b'idek{' in flag:
					print(flag)
					con.close()
					exit(int(0));

for _ in range(10):
	con = server = conn()
	solve(con)
	con.close()
exit(int(1))