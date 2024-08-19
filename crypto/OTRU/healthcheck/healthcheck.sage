#!/usr/bin/env sage

from sage.all import *
from pwn import *
import os
import random
from Crypto.Util.number import bytes_to_long as b2l
from Crypto.Util.number import long_to_bytes as l2b

def split(M, k, L):

	_ = bin(M)[2:].zfill(L)
	l = L // k

	return [int(_[i * l: (i + 1) * l], 2) for i in range(k)] 

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

def conn():

	r = remote('localhost', 1337)

	print(r.recvuntil(b'== proof-of-work: '))
	if r.recvline().startswith(b'enabled'):
		handle_pow(r)

	return r
	# if __debug__:
	# 	return process(["sage", "./server.sage"])
	# else:
	# 	exit()

def solve():
	server = conn()

	"""
		Read the outputs
	"""
	Zx.<x> = ZZ[]

	server.recvuntil(b"enc1 = ")
	enc1 = sage_eval(server.recvline().decode().strip(), locals = {"x" : x})
	server.recvuntil(b"enc2 = ")
	enc2 = sage_eval(server.recvline().decode().strip(), locals = {"x" : x})

	server.recvuntil(b"N = ")
	N = int(server.recvline())

	Q = QuaternionAlgebra(Zmod(N), -1, -1)
	i, j, k = Q.gens()

	"""
	server.recvuntil("x1 = ")
	x1 = sage_eval(server.recvline().decode().strip(), locals = {"i": i, "j": j, "k": k})
	server.recvuntil("x2 = ")
	x2 = sage_eval(server.recvline().decode().strip(), locals = {"i": i, "j": j, "k": k})
	"""

	server.sendline(b"0, 0, 0, 0")
	server.recvuntil(b"c1 = ")
	_ = server.recvline().decode().strip().split(", ")
	c00 = sage_eval(_[0][1:], locals = {"i": i, "j": j, "k": k})
	c01 = sage_eval(_[1][:-1], locals = {"i": i, "j": j, "k": k})
	server.recvuntil(b"c2 = ")
	_ = server.recvline().decode().strip().split(", ")
	c10 = sage_eval(_[0][1:], locals = {"i": i, "j": j, "k": k})
	c11 = sage_eval(_[1][:-1], locals = {"i": i, "j": j, "k": k})

	"""
		Recover the private keys partially by LLL
	"""

	def partial_key_recovery(c, n):

		c_a, c_b, c_c, c_d = c.coefficient_tuple()
		
		M = Matrix(ZZ, [
			[c_c, 0  , 1, 0, 0],
			[c_b, c_d, 0, 1, 0],
			[0  , c_c, 0, 0, 1],
			[N  , 0  , 0, 0, 0],
			[0  , N  , 0, 0, 0]
		])

		M = M.LLL()

		nn = n // 4
		poly = [0] * nn
		for i in range(2, 5):
			val = abs(M[0][i])
			L = nn if i != 4 else (n - nn * 3)
			for _ in range(L):
				poly += [int(val % 3) - 1]
				val //= 3

		return poly

	"""
		NTRU private keys attack with 75% consecutive bits known
	"""

	def key_recovery(f, f3, n):
		
		assert len(f) == len(f3) == n

		nn = n // 4

		# Construct the matrix based on f * f3 = 1 (mod 3)
		M = Matrix(Zmod(3), nn * 2, nn * 2)
		v = vector(Zmod(3), [0] * (nn * 2))

		for k in range(nn * 2, nn * 4):
			# The coefficient of x^k of f * f3
			for i in range(n):
				j = (k - i) % n
				if i < nn:
					M[k - nn * 2, i] = f3[j]
				elif j < nn:
					M[k - nn * 2, j + nn] = f[i]
				else:
					v[k - nn * 2] -= (f[i] * f3[j])	
		
		s = M.solve_right(v)
		for i in range(nn):
			f[i]  = s[i]      if s[i]      != 2 else -1
			f3[i] = s[i + nn] if s[i + nn] != 2 else -1

		return Zx(f), Zx(f3)

	n, q = 263, 128

	def conv(f, g):

		return (f * g) % (x^n - 1)

	def bal_mod(f, q):

		coef = list(
			( (f[idx] + q // 2) % q ) - q // 2 for idx in range(n)
		)
		return Zx(coef)  % (x^n - 1)

	def decode(poly):

		val = 0
		for idx in range(n):
			val += (poly[idx] + 1) * 3^idx
		return val

	def NTRU_decrypt(enc, priv_key):

		f, f3 = priv_key
		_ = bal_mod(conv(f, enc), q)
		_ = bal_mod(_, 3)
		_ = bal_mod(conv(f3, _), 3)

		return decode(_)

	def OTRU_decrypt(enc, c):

		f  = partial_key_recovery(c[0], n)
		f3 = partial_key_recovery(c[1], n)
		f, f3 = key_recovery(f, f3, n)

		return l2b(NTRU_decrypt(enc, (f, f3)))

	nonce1 = OTRU_decrypt(enc1, (c00, c01))
	nonce2 = OTRU_decrypt(enc2, (c10, c11))

	server.sendline((nonce1 + nonce2).hex())
	_ = server.recvline()
	flag = server.recvline().decode()
	if b'idek{' in flag:
		exit(int(0));

for _ in range(5):
	try:
		solve()
	except:
		pass
