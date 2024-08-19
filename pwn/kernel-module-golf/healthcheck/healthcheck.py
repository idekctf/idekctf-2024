#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))



import base64

exploit = open("/home/user/exploit", "rb").read()

def solve():
    p = remote('127.0.0.1', 1337)
    try:
        print(p.recvuntil(b'== proof-of-work: '))
        if p.recvline().startswith(b'enabled'):
            handle_pow(p)

        p.sendlineafter(b": ", base64.b64encode(exploit))

        p.sendlineafter(b"~ $", b'/bin/pwn')

        p.sendlineafter(b"~ #", b'cat /root/flag.txt')
        p.recvline()
        if b'idek{' in p.recv():
            exit(0)
    except EOFError:
        pass
    p.close()

for _ in range(10):
    solve()
