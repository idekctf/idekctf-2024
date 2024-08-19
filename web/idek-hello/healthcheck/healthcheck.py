#!/usr/bin/env python3
import requests

r = requests.get('http://localhost:1337')
assert r.status_code == 200

r = requests.get('http://localhost:1337/?name=aaa')
assert b'aaa' in r.content

r = requests.get('http://localhost:1337/info.php')
assert r.status_code == 404

r = requests.get('http://localhost:1337/info.php/a.php')
assert r.status_code == 200

exit(0)