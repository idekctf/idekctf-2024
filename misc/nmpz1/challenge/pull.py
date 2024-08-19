import itertools
import json
import logging
import math
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import backoff
import httpx

logging.getLogger("backoff").addHandler(logging.StreamHandler())

with open("challs.json") as f:
    challs = json.load(f)
chall_dir = "./public/img"
force_flag = sys.argv[1] == "--force" if len(sys.argv) > 1 else False

print(json.dumps(challs, indent=2))


@backoff.on_exception(backoff.expo, Exception)
def get_img(part, part_name, chall, x, y, z):
    if part["panoType"] == 1:
        url = f"https://streetviewpixels-pa.googleapis.com/v1/tile?cb_client=maps_sv.tactile&panoid={part['pano']}&x={x}&y={y}&zoom={z}&nbt=1&fover=2"
    else:
        url = f"https://lh3.ggpht.com/p/{part['pano']}=x{x}-y{y}-z{z}"
    resp = httpx.get(url)
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        if e.response.status_code in {400, 404}:
            print(f"{e.response.status_code} {chall}/{part_name}/tile_{x}_{y}_{z}.jpeg")
            return
        raise

    with open(f"{chall_dir}/{chall}/{part_name}/tile_{x}_{y}_{z}.jpeg", "wb") as f:
        f.write(resp.content)
    print(f"{chall}/{part_name}/tile_{x}_{y}_{z}.jpeg")


with ThreadPoolExecutor(max_workers=50) as ex:
    for chall, parts in challs.items():
        os.makedirs(f"{chall_dir}/{chall}", exist_ok=True)

        for part_name, part in parts.items():
            if os.path.exists(f"{chall_dir}/{chall}/{part_name}"):
                if not force_flag:
                    continue
                else:
                    os.system(f"rm -r {chall_dir}/{chall}/{part_name}")
            else:
                os.makedirs(f"{chall_dir}/{chall}/{part_name}")

            for z in range(part["maxZ"] + 1):
                for x, y in itertools.product(range(2**z), range(math.ceil(2 ** (z - 1)))):
                    ex.submit(get_img, part, part_name, chall, x, y, z)

    ex.shutdown(wait=True)
