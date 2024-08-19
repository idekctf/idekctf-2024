from collections import namedtuple
import keyword
import string
from Crypto.Util.number import getPrime
from Crypto.Cipher import ARC4
from tea import TEA
import coolname
import random
from pwn import p32, p16
import os
import hashlib
from ctypes import CDLL
import numpy as np
import tqdm

libc = CDLL("libc.so.6")

_func_name_generator: any = None

def set_func_gen(generator):
    global _func_name_generator
    _func_name_generator = generator

def gen_func_name():
    return '_'.join(_func_name_generator.generate())

def gen_random_string():
    return ''.join(random.choices(string.ascii_letters, k=30))

def generate(filename, keywords, entrypoint, cb_replacements):
    code_c = open(f'templates/{filename}.c','r').read()
    code_h = open(f'templates/{filename}.h', 'r').read()
    replacements = {k: gen_func_name() for k in keywords}

    enc, denc = cb_replacements(replacements)

    for frm, to in replacements.items():
        code_c = code_c.replace(frm, to)
        code_h = code_h.replace(frm, to)
    
    orig_filename = filename + '.h'
    def gen_source(filename):
        return code_c.replace(orig_filename, filename)

    # .c filename, .h filename
    return gen_source, code_h, replacements[entrypoint], enc, denc



def generate_matrix():
    modulus_t = '41389'
    srand_seed = '1337'
    entrypoint = 'matrix_entry'
    keywords = [
        'init_matrix',
        'free_mat',
        'init_identity',
        'rref_add',
        'rref_mul',
        'genRandomInvertibleMatrix',
        'Matrix_t',
        'MOD',
        srand_seed,
        entrypoint,
        modulus_t
    ]

    def callback(replacements):
        modulus = getPrime(16)
        while modulus <= 256:
            modulus = getPrime(16)

        seed = random.getrandbits(31)
        replacements[srand_seed] = str(seed)
        replacements[modulus_t] = str(modulus)

        def identity(n):
            mat = [[0] * n for _ in range(n)]
            for i in range(n):
                mat[i][i] = 1
            return mat

        def rescale_row(mat, i, a):
            if a == 0:
                return
            for j in range(len(mat[i])):
                mat[i][j] *= a
                mat[i][j] %= modulus
        
        def add_row(mat, a, b):
            if a == b:
                return
            for j in range(len(mat[a])):
                mat[a][j] += mat[b][j]
                mat[a][j] %= modulus

        def gen_matrix(n, seed):
            mat = identity(n)
            libc.srand(seed)
            for _ in range(n*n):
                if libc.rand() % 2:
                    a = libc.rand()%n
                    b = libc.rand()%n
                    add_row(mat, a, b)
                else:
                    a = libc.rand()%n
                    b = libc.rand()%modulus
                    rescale_row(mat, a, b)
            return mat

        def enc(pt) -> str:
            mat = np.array(gen_matrix(len(pt), seed))
            vec = np.array(list(pt))
            res = list(mat.dot(vec) % modulus)
            return b''.join(p16(a) for a in res)
        
        def denc(ct) -> str:
            raise Exception()

        return enc, denc

    return generate('matrix', keywords, entrypoint, callback)


def generate_rc4():
    key_t = 'PLACEHOLDER'
    key_len_t = '1337'
    entrypoint = 'rc4_entry'
    keywords = [
        'encrypt_rc4',
        'genByte',
        'init_rc4',
        'swap_rc4',
        'rc4_t',
        key_t,
        key_len_t,
        entrypoint,
    ]
    
    def callback(replacements):
        key = gen_random_string()
        replacements[key_t] = key
        replacements[key_len_t] = str(len(replacements[key_t]))

        def enc(pt) -> str:
            cipher = ARC4.new(key.encode())
            return cipher.encrypt(pt)
        
        def denc(ct) -> str:
            cipher = ARC4.new(key.encode())
            return cipher.decrypt(ct)
    
        return enc, denc

    return generate('rc4', keywords, entrypoint, callback)

def generate_sbox():
    key_t = 'PLACEHOLDER'
    entrypoint = 'sbox_entry'
    keywords = [
        key_t,
        entrypoint
    ]
    
    def callback(replacements):
        sbox = list(range(256))
        random.shuffle(sbox)
        rbox = [sbox.index(i) for i in range(256)]
        replacements[key_t] = ', '.join(str(a) for a in sbox)

        def enc(pt) -> str:
            return bytes([sbox[ch] for ch in pt])
    
        def denc(ct) -> str:
            return bytes([rbox[ch] for ch in ct])

        return enc, denc

    return generate('sbox', keywords, entrypoint, callback)

# from itertools import product
# import hashlib

# sha1_lookup = {}

# for a in product(range(256), repeat=3):
# 	b = hashlib.sha1(bytes(a)).digest()[:6]
# 	assert b not in sha1_lookup, f"{a} {sha1_lookup[b]}"
# 	sha1_lookup[b] = bytes(a)

def generate_sha1():
    entrypoint = 'sha1_entry'
    keywords = [
        'sha_ctx',
        'sha1_hash',
        'sha1_final',
        'sha1_update',
        'sha1_init',
        'sha1_transform',
        entrypoint
    ]
    
    def sha1(pt):
        return hashlib.sha1(pt).digest()

    def callback(replacements):
        def enc(pt) -> str:
            pt += bytes((3 - (len(pt) % 3)) % 3)
            return b''.join([sha1(pt[i:i+3])[:6] for i in range(0, len(pt), 3)])
    
        def denc(ct) -> str:
            raise Exception()
            # return b''.join([sha1_lookup[ct[i:i+6]] for i in range(0, len(ct), 6)])

        return enc, denc

    return generate('sha1', keywords, entrypoint, callback)

def generate_tea():
    entrypoint = 'tea_entry'
    key_t = 'PLACEHOLDER'
    keywords = [
        'encrypt_tea',
        key_t,
        entrypoint
    ]
    
    def callback(replacements):
        key = [random.getrandbits(32) for _ in range(4)]
        key_s = b''.join(p32(a) for a in key)

        replacements[key_t] = ', '.join(map(str, key))
        def enc(pt) -> bytes:
            cipher = TEA(bytes(key_s), endian='<')
            return cipher.encrypt_all(pt)
    
        def denc(ct) -> bytes:
            cipher = TEA(bytes(key_s), endian='<')
            return cipher.decrypt_all(ct)

        return enc, denc

    return generate('tea', keywords, entrypoint, callback)

Context = namedtuple("Context", "gen_source h_source entrypoint enc denc")

def gen_main(headers, sources, res, code, passcode):
    headers = [f'#include "{header}"' for header in headers]
    sources = [f'#include "{source}"' for source in sources]
    enc = res
    res = "{" + ', '.join([str(a) for a in res]) + "};"
    main_c = f'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/resource.h>
{'\n'.join(headers)}

/* END INCLUDE SECTION */
{'\n'.join(sources)}

int main(){{
    uint8_t buf[{len(passcode)}+1];
    struct rlimit rlim;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (getrlimit(RLIMIT_STACK, &rlim)) {{
        puts("Unable to fetch stack size");
        return 1;
    }}
    rlim.rlim_cur = 1024 * 1024 * 32;
    if (setrlimit(RLIMIT_STACK, &rlim)) {{
        puts("Unable to grow stack size");
        return 1;
    }}
    uint8_t* enc = (uint8_t[]){res}
    printf("> ");
    int len = read(0, buf, {len(passcode)});
    struct string s;
	s.buf = malloc(len);
	s.len = len;
	memcpy(s.buf, buf, len);
    {'\n'.join(code)}
    if(s.len == {len(enc)} && memcmp(s.buf, enc, {len(enc)}) == 0){{
        puts(":)");
    }}else{{
        puts(":(");
    }}
    return 0;
}}
'''
    return main_c

def gen_init() -> list[Context]:
    return []

def gen_update(ctx: list[Context], func):
    gen_source, h_source, entrypoint, enc, denc = func()
    ctx.append(Context(gen_source, h_source, entrypoint, enc, denc))

def eval_composition(funcs, arg):
    for func in funcs:
        # print(len(arg), func)
        arg = func(arg)
    return arg

def save_code(filename, data, directory):
    f = open(f'./srcs/{directory}/{filename}', 'w')
    f.write(data)
    f.close()

def gen_final(ctx: list[Context], passcode: bytes, directory: bytes):
    filenames = [gen_func_name() for _ in range(len(ctx))] 
    headers = [filename + '.h' for filename in filenames]
    sources = [filename + '.c' for filename in filenames]
    main_code = [f'{c.entrypoint}(&s);' for c in ctx]
    enc = eval_composition([c.enc for c in ctx], passcode)
    save_code('main.c', gen_main(['util.h'] + headers, sources, enc, main_code, passcode), directory)

    for i in range(len(ctx)):
        save_code(headers[i], ctx[i].h_source, directory)
        save_code(sources[i], ctx[i].gen_source(headers[i]), directory)
    
    os.system(f'cp ./templates/util.h ./srcs/{directory}/util.h')

def gen(passcode, directory, generator, N=15):
    generators = [
        (generate_matrix, 2, 300), # 2n
        (generate_rc4, 1, None), # n
        (generate_sbox, 1, None), # n
        (generate_sha1, 2, None), # 2n
        (generate_tea, 1, None) # n
    ]

    set_func_gen(generator)

    os.system(f"rm -f ./srcs/{directory}/*")
    ctx = gen_init()
    cur_len = len(passcode)
    for _ in range(N):
        generator, mul, max_len = random.choice(generators)
        while max_len is not None and cur_len > max_len:
            generator, mul, max_len = random.choice(generators)
        
        cur_len *= mul
        gen_update(ctx, generator)
    gen_final(ctx, passcode, directory)


if __name__ == '__main__':
    os.system(f"mkdir ./srcs/0")
    random.seed(1)
    gen(b'idek{now_do_this_9999_more_times}\n', 'baby')