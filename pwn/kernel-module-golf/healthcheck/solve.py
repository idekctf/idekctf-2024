from pwn import *
import base64

exploit = open("exploit", "rb").read()

p = process("python3 ../challenge/upload.py", shell=True, cwd="../challenge")
p.sendlineafter(b": ", base64.b64encode(exploit))

p.interactive()