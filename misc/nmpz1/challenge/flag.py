import json

from Crypto.Cipher import AES
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

FLAG1 = b"idek{}"
FLAG2 = b"idek{}"
FLAG3 = b"idek{}"

SHARES, NEEDED = 10, 9

NONCE1, TAG1, CT1 = "02b47769e46dcda129b4826e837a68fe", "62e15bbf31eb5c77c8c250f711fd50cc", "0ac599f8dc4d58887cec52553c47e13f5924244765c5da265923cf3feb919b07"
NONCE2, TAG2, CT2 = "8197849a380afd25a879fa24dd38f743", "a2acb79c00de956a5cabd6fbe1c07201", "1fc185f62d2b6876bff9b107cfa12b3f525d68cc5db79158977416a07aa59d477bd390a4b142c38ffa79b776f01a7d79341cb7"
NONCE3, TAG3, CT3 = "3164c1cf2940d40e8ad8961eefcd9c6e", "df7b1a31f14430973383bfdc4b532c9c", "9b229a98db00e3d8d61ab227e1cff8b9ee1281918bc508ecf1b6573fa2bac83637af1bf8562358e30378e2880f0817b725"


def encrypt(flag, key=None):
    if key is None:
        key = get_random_bytes(16)
    shares = Shamir.split(NEEDED, SHARES, key)
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt(flag), cipher.digest()

    return shares, cipher.nonce, tag, ct


def input_shares_to_chall(level, shares):
    with open("challs.json") as f:
        challs = json.load(f)

    parts = challs[level]
    assert len(shares) == len(parts)

    for (idx, share), part in zip(shares, parts.values()):
        part["flag"] = f"{idx},{share.hex()}"

    with open("challs.json", "w") as f:
        json.dump(challs, f, indent=4)


def decrypt():
    shares = []
    for _ in range(NEEDED):
        in_str = input("Enter index,share: ")
        idx, share = in_str.strip().split(",")
        shares.append((int(idx), bytes.fromhex(share)))

    key = Shamir.combine(shares)
    for nonce, tag, ct in [(NONCE1, TAG1, CT1), (NONCE2, TAG2, CT2), (NONCE3, TAG3, CT3)]:
        cipher = AES.new(key, AES.MODE_EAX, bytes.fromhex(nonce))
        result = cipher.decrypt(bytes.fromhex(ct))
        try:
            cipher.verify(bytes.fromhex(tag))
        except ValueError:
            continue
        print(result)


# for flag, level in zip([FLAG1, FLAG2, FLAG3], ["easy", "medium", "hard"]):
#     shares, nonce, tag, ct = encrypt(flag)
#     print(nonce.hex())
#     print(tag.hex())
#     print(ct.hex())
#     input_shares_to_chall(level, shares)

decrypt()
