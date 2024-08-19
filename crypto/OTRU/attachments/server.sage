from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import getPrime
import random
import os

n, q = 263, 128
Zx.<x> = ZZ[]

_p, _q = getPrime(512), getPrime(512)
N = _p * _q
e = getPrime(768)
d = int(inverse_mod(e, (_p^2 - 1) * (_p^2 - _p) * (_q^2 - 1) * (_q^2 - _q)))
Q = QuaternionAlgebra(Zmod(N), -1, -1)
i, j, k = Q.gens()

def conv(f, g):
	
	return (f * g) % (x^n - 1)

def bal_mod(f, q):

	coef = list(
		( (f[idx] + q // 2) % q ) - q // 2 for idx in range(n)
	)
	return Zx(coef)  % (x^n - 1)

def rand_poly(d1, d2):

	coef = d1 * [1] + d2 * [-1] + (n - d1 - d2) * [0]
	random.shuffle(coef)
	return Zx(coef)

def inv_mod_p(f, p):

	T = Zx.change_ring(Zmod(p)).quotient(x^n - 1)
	return Zx(lift(1 / T(f)))

def inv_mod_2k(f, q):

	assert q.is_power_of(2)
	g = inv_mod_p(f, 2)

	while True:
		r = bal_mod(conv(g, f), q)
		if r == 1: return g
		g = bal_mod(conv(g, 2 - r), q)

def key_gen():

	while True:
		try:
			f = rand_poly(61, 60)
			f3 = bal_mod(inv_mod_p(f, 3), 3)
			fq = inv_mod_2k(f, q)
			break
		except:
			pass
	g = rand_poly(20, 20)
	
	pub_key = bal_mod(3 * conv(fq, g), q)
	priv_key = (f, f3)

	return pub_key, priv_key

def encode(val):

	poly = 0
	for idx in range(n):
		poly += ( (val % 3) - 1 ) * x^idx
		val //= 3
	return poly

def decode(poly):

	val = 0
	for idx in range(n):
		val += (poly[idx] + 1) * 3^idx
	return val

def poly_to_Q(poly):

	nn = n // 4
	start = [idx * nn for idx in range(4)] + [n]
	coef = []

	for idx in range(4):
		val = 0
		for jdx in range(start[idx], start[idx + 1]):
			val += (poly[jdx] + 1) * 3^(jdx - start[idx])
		coef += [val]

	return (coef[0] + coef[1] * i + coef[2] * j + coef[3] * k)

def qow(q, x):

	return q ** int(sum(x.coefficient_tuple()))

def encrypt(m, pub_key):

	r = rand_poly(18, 18)

	return bal_mod(conv(pub_key, r) + encode(m), q)

if __name__ == '__main__':

	pub_key1, priv_key1 = key_gen()
	pub_key2, priv_key2 = key_gen()

	nonce1 = os.urandom(16)
	nonce2 = os.urandom(16)

	print(f"enc1 = {encrypt(b2l(nonce1), pub_key1)}")
	print(f"enc2 = {encrypt(b2l(nonce2), pub_key2)}")

	print("A free gift for you, I'm so kind!")
	print(f"N = {N}")

	x1, x2 = poly_to_Q(rand_poly(20, 24)), poly_to_Q(rand_poly(20, 24))
	
	"""
		Pick a random r and compute v = r**e + x1/x2
		Then k1 or k2 = r and you should be able to retrieve the corresponding key
	"""

	coef = input("Give me your choice: ").split(", ")
	v = int(coef[0]) + int(coef[1]) * i + int(coef[2]) * j + int(coef[3]) * k

	k1 = (v - x1) ** d
	k2 = (v - x2) ** d

	c1 = (qow(poly_to_Q(priv_key1[0]), k1), qow(poly_to_Q(priv_key1[1]), k1))
	c2 = (qow(poly_to_Q(priv_key2[0]), k2), qow(poly_to_Q(priv_key2[1]), k2))

	print(f"c1 = {c1}")
	print(f"c2 = {c2}")

	guess = bytes.fromhex(input("Make a guess: "))

	if guess == nonce1 + nonce2:
		print(":>")
		flag = os.getenv("flag", "idek{fake_flag}").encode()
		print(flag)
	else:
		print(":<")
