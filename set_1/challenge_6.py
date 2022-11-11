import operator
import base64
import os
import math
import string

DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_6.txt")

# ALLOWED_CHARS = set(bytes(string.ascii_letters + string.digits + string.whitespace + "!\"'(),-./:;=?", "ascii"))
ALLOWED_CHARS = set(bytes(string.printable, "ascii"))


def is_allowed_char(c):
    return c in ALLOWED_CHARS


def decryption_score(s):
    return (s.count(b"e") + s.count(b"E") + s.count(b"t") + s.count(b"T") + s.count(b" "))


key = []


def decipher_block(s):
    candidates = {}

    for i in range(256):
        candidate = bytes(map(lambda c:  c ^ i, s))
        if all(map(is_allowed_char, candidate)):
            candidates[i] = candidate

    ret = max(candidates.items(), key=lambda i: decryption_score(i[1]))
    key.append(chr(ret[0]))
    return ret[1]


def edit_distance(s1, s2):
    xored = map(operator.xor, s1, s2)
    return bin(int.from_bytes(xored, byteorder='big')).count("1")


data = base64.b64decode(open(DATA_PATH).read())

keysize_candidates = {}

for i in range(2, 41):
    keysize_candidates[i] = edit_distance(data[:3*i], data[3*i:6*i]) / i

for keysize in sorted(keysize_candidates, key=lambda size: keysize_candidates[size])[:5]:
    print("keysize:", keysize)

    blocks = [data[i::keysize] for i in range(keysize)]

    print(b"".join(map(bytes, zip(*[decipher_block(block) for block in blocks]))).decode("utf-8"))
    # print(key)


def xor_with_key(s, key):
    return base64.b16encode(bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s)))
