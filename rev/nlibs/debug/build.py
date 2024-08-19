import glob
import os
from gen_sources import gen as gen_code
from clean import clean as clean_code
from obf import obfuscate
import random
import json
from coolname import RandomGenerator
import tqdm
from tqdm.contrib.concurrent import process_map  # or thread_map
from multiprocessing import Pool

class UniqueGenerator():
    def __init__(self, config):
        self.generator = RandomGenerator(config)
        self.seen = set()
    
    def generate(self):
        while True:
            name = tuple(self.generator.generate())
            if name not in self.seen:
                self.seen.add(name)
                return list(name)


def clean():
    paths = glob.glob('./srcs/*/main.c99')
    for path in paths:
        os.remove(path)

N = 15

def gen(passcode, directory, config, N=15):
    generator = UniqueGenerator(config)

    os.system(f"mkdir -p ./srcs/{directory} ./build/{directory} ./out/{directory}")
    gen_code(passcode, directory, generator, N=N)
    assert os.system(f'gcc -E -C srcs/{directory}/main.c -o srcs/{directory}/main.c99') == 0
    clean_code(directory)
    obfuscate(directory, generator, f'../../out/{directory}')
    assert os.system(f'cp srcs/{directory}/*.h build/{directory}/') == 0

def gen_packed(arg):
    gen(*arg)

def gen_build_make():
    make_contents = b'''
SUBDIRS := $(wildcard */.)

all: $(SUBDIRS)

$(SUBDIRS):
\t$(MAKE) -C $@

.PHONY: all $(SUBDIRS)
'''
    f = open('build/Makefile','wb')
    f.write(make_contents)
    f.close()


def make():
    config = json.loads(open('coolnames.json','r').read())
    clean()
    random.seed(1)
    gen(b'idek{now_do_this_9999_more_times}', 'baby', config, 15)
    f = open('flag.jpg','rb')
    flag = f.read()
    k = 128
    N = len(flag)
    print(N//k)

    random.seed(None)
    args = []
    for i in range(0, N, k):
        args.append((flag[i:i+k], str(i//k), config, 5))
    
    gen_build_make()
    with Pool(24) as p:
        list(tqdm.tqdm(p.imap_unordered(gen_packed, args), total=len(args)))
        # list(tqdm.tqdm(p.imap(gen_packed, args), total=len(args)))
    

    

make()
