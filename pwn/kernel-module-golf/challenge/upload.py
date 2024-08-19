#!/usr/bin/env python3
import base64
import tempfile
import os

exploit = base64.b64decode(input("input your exploit (base64): "))

assert len(exploit) < 64 * 1024

with tempfile.NamedTemporaryFile() as fp:
    fp.write(exploit)
    fp.flush()

    os.system(f"/home/user/run.sh {fp.name}")