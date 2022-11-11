import base64
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from collections import Counter
import os
import string


DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_20.txt")


ALLOWED_CHARS = set(bytes(string.ascii_letters + string.whitespace +
                          string.digits + r"""!"$%&'()*+,-./:;<=>?@`""", "ascii"))


def is_allowed_char(c):
    return c in ALLOWED_CHARS


def decryption_score(s):
    return (s.count(b"e") + s.count(b"E") + s.count(b"t") + s.count(b"T") + s.count(b" ") + s.count(b"A"))


def decrypt_block(s):
    candidates = {}

    for i in range(256):
        candidate = bytes(map(lambda c:  c ^ i, s))
        if all(map(is_allowed_char, candidate)):
            candidates[i] = candidate

    ret = max(candidates.items(), key=lambda i: decryption_score(i[1]))
    return ret[1]


def xor_with_key(s, key):
    return bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s))


class AES_CTR:
    def __init__(self, key, nonce):
        self._aes = AES.new(key, AES.MODE_ECB)
        self._key = key
        self._nonce = nonce

    def encrypt(self, data):
        result = []
        for i in range(len(data)):
            block = data[i * len(self._key):(i + 1) * len(self._key)]
            cur_key = self._aes.encrypt(struct.pack("<QQ", self._nonce, i))
            result.append(xor_with_key(block, cur_key))

        return b"".join(result)

    def decrypt(self, data):
        return self.encrypt(data)


KEY = get_random_bytes(16)
CIPHER = AES_CTR(KEY, 0)

DATA = list(map(lambda t: CIPHER.encrypt(base64.b64decode(t)), open(DATA_PATH)))


def main():
    blocks = zip(*DATA)
    decrypted_blocks = map(decrypt_block, blocks)
    for block in zip(*decrypted_blocks):
        print(bytes(block))


if __name__ == "__main__":
    main()
