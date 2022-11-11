from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
import os
import base64

BLOCK_SIZE = 16
KEY = b"YELLOW SUBMARINE"
IV = b'\0' * BLOCK_SIZE


def remove_padding(data: bytes):
    assert len(data) % BLOCK_SIZE == 0, "data is not padded to key size"
    if data == b"":
        return data
    padding_size = data[-1]
    assert 0 != padding_size and bytes([padding_size] * padding_size) == data[-padding_size:], "Invalid padding"
    return data[:-padding_size]


def pad(data, size=BLOCK_SIZE):
    padding_size = (size - (len(data) % size))
    if padding_size == 0:
        padding_size = size
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


def CBC_MAC(message):
    return AES_CBC(KEY, IV).encrypt(pad(message))[-BLOCK_SIZE:]


def main():
    original_code = b"alert('MZA who was that?');\n"
    assert CBC_MAC(original_code).hex() == "296b8d7cb78a243dda4d0a61d33bbdd1"
    forged_js = pad(b"alert('Ayo, the Wu is back!'); //")
    forged_js += xor_with_key(original_code[:BLOCK_SIZE], CBC_MAC(remove_padding(forged_js)))
    forged_js += original_code[BLOCK_SIZE:]
    assert CBC_MAC(forged_js) == CBC_MAC(original_code)

    result_path = os.path.dirname(__file__) + "/results/challenge_50.html"
    with open(result_path, "wb") as f:
        f.write(b"<script>" + forged_js + b"</script>")


if __name__ == "__main__":
    main()
