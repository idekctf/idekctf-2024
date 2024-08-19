#!/usr/bin/env python3
from pwn import *
import tempfile
import base64
import os

tmp = tempfile.TemporaryFile()
context.log_level = "ERROR"
BIN_PATH = tmp.name


def get_binary(io):
    io.recvuntil(b"----------------")
    b64_binary = io.recvuntil(b"----------------", drop=True)
    binary_data = base64.b64decode(b64_binary)
    with open(BIN_PATH, "wb") as f:
        f.write(binary_data)
    return binary_data


def is_elf(binary_data):
    return binary_data.startswith(b"\x7fELF")


def main():
    io = remote("127.0.0.1", 1337)
    binary_data = get_binary(io)

    if not is_elf(binary_data):
        print("The binary is not a valid ELF file!")
        exit(-1)

    payload = b"some really wrong payload"
    b64_payload = base64.b64encode(payload)
    io.sendlineafter(b"solution:\n", b64_payload)
    should_be_wrong = io.recvline()
    if b"You failed!" not in should_be_wrong:
        print("Something is not working as expected!")
        exit(-1)

    print("Everything should be working!")

    if os.path.exists(BIN_PATH):
        os.remove(BIN_PATH)
    
    exit(0)


main()