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
    def __init__(self, c, size):
        self.c = c
        self.calls = 0
        self.size = size

    def __call__(self, msg, h=b"\0"):
        for block in get_blocks(msg, BLOCK_SIZE):
            self.calls += 1
            h = self.c(block, h)
        return h


def crypto_hash(key, start, size):
    cipher = AES.new(key, mode=AES.MODE_ECB)

    def func(block, h):
        return cipher.encrypt(xor_with_key(block, h))[start:start + size]
    return func


my_hash = MD(crypto_hash(b"YELLOW SUBMARINE", 0, 3), 3)


class Collisions:
    def __init__(self, func, k):
        self._k = k
        self._func = func
        self._collisions_data = self._generate_collision_tree(k)

    def _get_collision(self, h1, h2):
        tried1 = {}
        tried2 = {}
        while True:
            data = get_random_bytes(BLOCK_SIZE - 1)
            hash_result1 = self._func(data, h1)
            hash_result2 = self._func(data, h2)
            if hash_result1 in tried2:
                return data, tried2[hash_result1], hash_result1
            elif hash_result2 in tried1:
                return tried1[hash_result2], data, hash_result2
            tried1[hash_result1] = data
            tried2[hash_result2] = data

    def _generate_collision_tree(self, k):
        cur = [i.to_bytes(self._func.size, 'little') for i in range(2**k)]
        collisions = []
        for i in range(k):
            next_states = []
            cur_collisions = []
            for h1, h2 in zip(cur[::2], cur[1::2]):
                cur_collision = self._get_collision(h1, h2)
                cur_collisions.extend(cur_collision[:-1])
                next_states.append(cur_collision[-1])
            cur = next_states
            collisions.append(cur_collisions)
        return collisions

    def get_by_path(self, n):
        s = []
        for i in range(self._k):
            s.append(self._collisions_data[i][n])
            n //= 2
        return b"".join(map(pad, s))

    def find_bridge(self, h):
        while True:
            data = get_random_bytes(BLOCK_SIZE - 1)
            hash_result = int.from_bytes(self._func(data, h), 'little')
            if hash_result <= 2**self._k:
                return data, hash_result

    def get_msg_by_prefix(self, msg):
        bridge, path = self.find_bridge(my_hash(msg))
        return pad(msg) + pad(bridge) + self.get_by_path(path)


def main():
    k = 8
    msg1 = b"I am Dean Sysman"
    msg2 = b"I am not Dean Sysman"
    collisions = Collisions(my_hash, k)

    forged1 = collisions.get_msg_by_prefix(msg1)
    forged2 = collisions.get_msg_by_prefix(msg2)
    print(my_hash(forged1), my_hash(forged2))
    print(my_hash.calls)


if __name__ == "__main__":
    main()
