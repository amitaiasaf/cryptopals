import zlib
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random

TEMPLATE_MESSAGE = b"""
POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: """

BLOCK_SIZE = 16


def pad(data, size=BLOCK_SIZE):
    padding_size = (size - (len(data) % size))
    if padding_size == 0:
        padding_size = size
    return data + padding_size.to_bytes(1, 'little') * padding_size


def format_message(message):
    return TEMPLATE_MESSAGE + str(len(message)).encode('ascii') + b'\n\n' + message


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


def encrypt(data):
    return AES.new(get_random_bytes(16), AES.MODE_CBC, iv=get_random_bytes(16)).encrypt(pad(data))


def compression_oracle(message):
    return len(encrypt(zlib.compress(format_message(message), -1)))


def get_compression_score(known_message, letter):
    result = sum(compression_oracle(
        (known_message + bytes([letter, i, 0xff]))[-BLOCK_SIZE:] * j) for i in range(128) for j in range(BLOCK_SIZE))
    print(letter, chr(letter), result)
    # result = compression_oracle(known_message _ bytes([]))
    return result


def main():
    message = b"sessionid="
    while b"Content" not in message:
        message += bytes([min(range(128), key=lambda i:get_compression_score(message, i))])
        print(message)


if __name__ == "__main__":
    main()
