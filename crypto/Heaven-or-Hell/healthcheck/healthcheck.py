#!/usr/bin/env python3
from pwn import *

def solve():
	def handle_pow(r):
		print(r.recvuntil(b'python3 '))
		print(r.recvuntil(b' solve '))
		challenge = r.recvline().decode('ascii').strip()
		p = process(['kctf_bypass_pow', challenge])
		solution = p.readall().strip()
		r.sendline(solution)
		print(r.recvuntil(b'Correct\n'))


	# con = process('./write_me_patched')
	con = remote('127.0.0.1', 1337)
	print(con.recvuntil(b'== proof-of-work: '))
	if con.recvline().startswith(b'enabled'):
		handle_pow(con)

	con.recvuntil(b'Make your choice carefully:')

	con.close()
	exit(0)

solve()