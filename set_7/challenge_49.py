from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
import os
import base64

BLOCK_SIZE = 16
KEY = get_random_bytes(BLOCK_SIZE)
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


def CBC_MAC(message, iv):
    return AES_CBC(KEY, iv).encrypt(pad(message))[-BLOCK_SIZE:]


class User:
    def __init__(self, uid):
        self._uid = uid

    def get_transaction_message(self, *transactions):
        for t in transactions:
            assert t[1] >= 0
        iv = get_random_bytes(BLOCK_SIZE)
        raw_message = (f'from={self._uid}&to=' +
                       ''.join(f'{to}:{amount};' for to, amount in transactions)).encode('ascii')
        return raw_message + CBC_MAC(raw_message, IV)


class Server:
    def __init__(self):
        pass

    def transact(self, transaction):
        message = transaction[:-BLOCK_SIZE]
        MAC = transaction[-BLOCK_SIZE:]
        assert CBC_MAC(message, IV) == MAC
        print(message)


def main():
    user = User(100)
    victim = User(200)
    server = Server()

    transaction = victim.get_transaction_message((314, 7))
    message = pad(transaction[:-BLOCK_SIZE])
    transaction_mac = transaction[-BLOCK_SIZE:]

    fake_transaction = user.get_transaction_message((3, 10), (100, 10000000))
    message += xor_with_key(fake_transaction[:BLOCK_SIZE], transaction_mac)
    message += fake_transaction[BLOCK_SIZE:]

    server.transact(message)


if __name__ == "__main__":
    main()
