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

def group_action(pub, priv):
	es = priv.copy()
	A = pub
	assert len(es) == len(primes)
	EC = to_weierstrass(A)
	while True:
		if all(e == 0 for e in es):
			break
		x = Fp(randint(1, p-1))
		r = Fp(x ** 3 + A * x ** 2 + x)
		s = kronecker_symbol(r, p)
		assert (2 * is_square(r)) - 1 == s
		I = [i for i, e in enumerate(es) if sign(e) == s]
		if len(I) == 0:
			continue
		if s == -1:
			EC = EC.quadratic_twist()
		while True:
			tmp = EC.random_element()
			if not tmp.is_zero():
				break
		x = tmp.xy()[0]
		t = prod([primes[i] for i in I])
		P = EC.lift_x(x)
		assert (p + 1) % t == 0
		Q = ((p + 1) // t) * P
		for i in I:
			assert t % primes[i] == 0
			R = (t // primes[i]) * Q
			if R.is_zero():
				continue
			phi = EC.isogeny(R)
			EC = phi.codomain()
			Q = phi(Q)
			assert t % primes[i] == 0
			t = t // primes[i]
			es[i] -= s
		if s == -1:
			EC = EC.quadratic_twist()
	return from_weierstrass(EC)

def truncated(n, ratio):

	kbits = int(n.bit_length() * ratio)
	return (n >> kbits) << kbits

class CSIDH:

	def __init__(self):
		self.priv = [randint(-2, 2) for _ in primes]
		self.pub = group_action(0, self.priv)

	def getPublic(self):
		return self.pub

	def getShare(self, other):
		return group_action(other, self.priv)

Angel, Devil = CSIDH(), CSIDH()
print(f"Angel's Public Key = {Angel.getPublic()}")
print(f"Devil's Public Key = {Devil.getPublic()}")

choice = input("Deal with [A]ngel or [D]evil? Make your choice carefully: ")
if choice == "A":
	for i in range(5):
		A = int(input("Enter the montgomery coefficient: "))
		print(truncated(int(Angel.getShare(A)), 0.4))
elif choice == "D":
	for i in range(4):
		D = int(input("Enter the montgomery coefficient: "))
		print(truncated(int(Devil.getShare(D)), 0.3))
else:
	print("Ok ... You are from Super Guesser, right?")	

S = int(Angel.getShare(Devil.getPublic()))
if int(input("Did Angel or Devil tell your the secret: ")) == S:
	try:
		f = open('flag.txt','r')
		FLAG = f.read()
		f.close()
	except:
		FLAG = "idek{debug}"
	print(f"FLAG = {FLAG}")
else:
	print("G_G")


