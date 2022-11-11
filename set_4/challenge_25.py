import struct
from Crypto.Cipher import AES
import os
import base64
from Crypto.Random import get_random_bytes, random


def xor_with_key(s, key):
    return bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s))


DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_25.txt")
ORIGINAL_DATA = base64.b64decode(open(DATA_PATH).read())


class AES_CTR:
    def __init__(self, key, nonce):
        self._aes = AES.new(key, AES.MODE_ECB)
        self._key = key
        self._nonce = nonce

    def encrypt(self, data, offset=0):
        result = []
        pad_size = (len(self._key) - offset % len(self._key))
        data = b"\0" * pad_size + data
        for i in range(len(data)):
            block = data[i * len(self._key):(i + 1) * len(self._key)]
            cur_key = self._aes.encrypt(struct.pack("<QQ", self._nonce, i + offset // len(self._key)))
            result.append(xor_with_key(block, cur_key))

        return b"".join(result)[pad_size:]

    def decrypt(self, data, offset=0):
        return self.encrypt(data, offset)


KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)
NONCE_SIZE = 64
NONCE = random.getrandbits(NONCE_SIZE)
CIPHER = AES_CTR(KEY, NONCE)


def get_encrypted_data():
    return list(CIPHER.encrypt(AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB).decrypt(ORIGINAL_DATA)))


def edit(ciphertext, offset, newtext):
    ciphertext[offset:offset + len(newtext)] = CIPHER.encrypt(newtext, offset)
    return ciphertext


def main():
    encrypted_data = get_encrypted_data()
    edited_data = edit(encrypted_data.copy(), 0, b"\0" * len(encrypted_data))
    print(xor_with_key(encrypted_data, edited_data))


if __name__ == "__main__":
    main()
