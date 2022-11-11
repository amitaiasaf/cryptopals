from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import itertools


BLOCK_SIZE = 16


def pad(data, size=BLOCK_SIZE):
    padding_size = (size - (len(data) % size))
    if padding_size == 0:
        padding_size = size
    return data + bytes([padding_size]) * padding_size


def xor_with_key(s, key):
    return bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s))


def get_blocks(data, size):
    data = pad(data, size)
    return (data[i:i+size] for i in range(0, len(data), size))


class MD(object):
    def __init__(self, c):
        self.c = c
        self.calls = 0

    def __call__(self, msg, h=b"\0"):
        for block in get_blocks(msg, BLOCK_SIZE):
            self.calls += 1
            h = self.c(block, h)
        return h

    def get_intermediate_hashes(self, msg):
        h = b"\0"
        hashes = {}
        for i, block in enumerate(get_blocks(msg, BLOCK_SIZE)):
            self.calls += 1
            h = self.c(block, h)
            hashes[h] = i + 1
        return hashes


def crypto_hash(key, start, size):
    cipher = AES.new(key, mode=AES.MODE_ECB)

    def func(block, h):
        return cipher.encrypt(xor_with_key(block, h))[start:start + size]
    return func


my_hash = MD(crypto_hash(b"YELLOW SUBMARINE", 0, 4))


class Collisions:
    def __init__(self, func, k):
        self._k = k
        self._func = func
        self._collisions_data = self._generate_expandable_collisions(k)
        self._h = self._func(self.get_by_length(self._k))

    def _get_collision(self, h, num_blocks):
        padding = b'\0' * (BLOCK_SIZE * num_blocks - 1)
        num_blocks_hash = self._func(padding, h)
        tried_single = {}
        tried_multiple = {}
        while True:
            data = get_random_bytes(BLOCK_SIZE - 1)
            hash_result = self._func(data, h)
            multi_hash_result = self._func(data, num_blocks_hash)
            if hash_result in tried_multiple:
                return data, pad(padding) + tried_multiple[hash_result], hash_result
            elif multi_hash_result in tried_single:
                return tried_single[multi_hash_result], pad(padding) + data, multi_hash_result
            tried_single[hash_result] = data
            tried_multiple[multi_hash_result] = data

    def _generate_expandable_collisions(self, k):
        cur = b'\0'
        collisions = []
        for i in range(k):
            cur_collision = self._get_collision(cur, 2**i)
            collisions.append(cur_collision[:-1])
            cur = cur_collision[-1]
        return collisions

    def get_by_length(self, n):
        n -= self._k
        s = []
        for i in range(self._k):
            s.append(self._collisions_data[i][n % 2])
            n //= 2
        return b"".join(map(pad, s))

    def find_bridge(self, intermediates):
        while True:
            data = get_random_bytes(BLOCK_SIZE - 1)
            hash_result = self._func(data, self._h)
            if hash_result in intermediates and self._k < intermediates[hash_result] <= self._k + 2**self._k:
                return data, intermediates[hash_result]


def main():
    k = 10
    msg = get_random_bytes(2**k * BLOCK_SIZE)
    collisions = Collisions(my_hash, k)
    bridge, i = collisions.find_bridge(my_hash.get_intermediate_hashes(msg))
    forged = pad(collisions.get_by_length(i - 1)) + pad(bridge) + msg[(i + i)*BLOCK_SIZE:]
    print(len(msg), len(forged))
    print(my_hash(msg), my_hash(forged))
    print(my_hash.calls)


if __name__ == "__main__":
    main()
