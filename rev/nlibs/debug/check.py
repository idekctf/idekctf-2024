from pwn import *
from pathlib import Path
import tqdm

context.log_level = 'critical'

def check(path: Path, ans) -> None:
    bin = path / 'main'
    con = process(str(bin.absolute()), cwd=path)
    con.send(ans)
    out = con.recvall()
    if out != b'> :)\n':
        print(con.poll(True))
        print("WTF", out, path, ans)

check(Path('out/baby/'), b'idek{now_do_this_9999_more_times}')

f = open('flag.jpg','rb')
flag = f.read()
k = 128
N = len(flag)
print(N//k)

random.seed(None)
args = []
for i in tqdm.tqdm(range(0, N, k)):
    ans = flag[i:i+k]
    dir = str(i//k)
    check(Path(f'out/{dir}/'), ans)