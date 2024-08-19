#!/usr/bin/env python3

import requests

r = requests.get("http://127.0.0.1:1337/api/post/3", cookies={"ADMIN_COOKIE": "0b8316282ad3dcd7a200e27229084e6c75a644e8c95bf725fe00054702070c81"})

if "idek{" in r.json()["content"]:
    exit(0)
exit(1)
