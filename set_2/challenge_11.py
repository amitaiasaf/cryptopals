from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random
import os
import base64
import collections

DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_11.txt")


def pad(data, size):
    padding_size = (size - (len(data) % size))
    return data + padding_size.to_bytes(1, 'little') * padding_size


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


def encryption_oracle(data):
    key = Random.get_random_bytes(16)
    data = Random.get_random_bytes(random.randrange(5, 10)) + data + Random.get_random_bytes(random.randrange(5, 10))
    data = pad(data, 16)
    if(random.choice([False, True])):
        print("using ECB")
        return AES.new(key, AES.MODE_ECB).encrypt(data)
    else:
        print("using CBC")
        return AES_CBC(key, Random.get_random_bytes(16)).encrypt(data)


def get_aes_mode(encrypted_data):
    if len(collections.Counter([encrypted_data[i: i + 16] for i in range(0, len(encrypted_data), 16)])) == len(encrypted_data) / 16:
        return "CBC"
    return "ECB"


def main():
    with open(DATA_PATH) as f:
        print("chosen mode is", get_aes_mode(encryption_oracle(pad(base64.b64decode(f.read()), 16))))


if __name__ == "__main__":
    main()
