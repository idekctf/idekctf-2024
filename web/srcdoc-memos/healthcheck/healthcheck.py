#!/usr/bin/env python3
import requests

# whereever the admin bot saves their memo to
REMOTE = "http://localhost:1337"

r = requests.get(REMOTE)
if "srcdoc memos" in r.text:
	exit(0)
exit(1)