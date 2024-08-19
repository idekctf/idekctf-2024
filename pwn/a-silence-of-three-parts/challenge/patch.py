from pwnc.minelf import ELF

raw_elf_bytes = open("chal", "rb").read()
elf = ELF(raw_elf_bytes)
last = next(filter(lambda segment: segment.type == 1, reversed(elf.segments)))
last.mem_size += 0x07000
with open("chal", "wb+") as fp:
    fp.write(elf.raw_elf_bytes)