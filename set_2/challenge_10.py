from Crypto.Cipher import AES
import os
import base64

DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_10.txt")


def xor_with_key(s, key):
    return bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s))


class AES_CBC:
    def __init__(self, key, initial_value):
        self._aes = AES.new(key, AES.MODE_ECB)
        self._key = key
        self._initial_value = initial_value

    def encrypt(self, data):
        last = self._initial_value
        result = []
        for i in range(0, len(data), len(self._key)):
            block = data[i:i+len(self._key)]
            result.append(self._aes.encrypt(xor_with_key(block, last)))
            last = result[-1]

        return b"".join(result)

    def decrypt(self, data):
        last = self._initial_value
        result = []
        for i in range(0, len(data), len(self._key)):
            block = data[i:i+len(self._key)]
            result.append(xor_with_key(self._aes.decrypt(block), last))
            last = block

        return b"".join(result)


cbc = AES_CBC(b"YELLOW SUBMARINE", b"\0" * 16)
data = base64.b64decode(open(DATA_PATH, "rb").read())
print(cbc.decrypt(data))
