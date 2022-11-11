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

    def __call__(self, msg, h):
        self.calls += 1
        for block in get_blocks(msg, BLOCK_SIZE):
            h = self.c(block, h)
        return h


def crypto_hash(key, start, size):
    cipher = AES.new(key, mode=AES.MODE_ECB)

    def func(block, h):
        return cipher.encrypt(xor_with_key(block, h))[start:start + size]
    return func


my_hash = MD(crypto_hash(b"YELLOW SUBMARINE", 0, 2))
more_expansive_hash = MD(crypto_hash(b"I Am Dean Sysman", 0,  4))


def get_collision(h, func):
    tried = {}
    while True:
        data = get_random_bytes(BLOCK_SIZE - 1)
        hash_result = func(data, h)
        if hash_result in tried:
            return tried[hash_result], data, hash_result
        tried[hash_result] = data


def generate_cheap_collisions(n, func):
    cur = b'\0'
    collisions = []
    for i in range(n):
        cur_collision = get_collision(cur, func)
        collisions.append(cur_collision[:-1])
        cur = cur_collision[-1]
    ret = []
    for p in itertools.product(*collisions):
        ret.append(b"".join(pad(b) for b in p[:-1]) + p[-1])
    return ret


def main():
    while True:
        cheap_collisions = generate_cheap_collisions(16, my_hash)
        print(len(cheap_collisions))
        tried = {}
        for collision in cheap_collisions:
            hash_result = more_expansive_hash(collision, b'\0')
            if hash_result in tried:
                print("collision found")
                print("calls to my_hash:", my_hash.calls)
                print("calls to more_expansive_hash:", more_expansive_hash.calls)
                return
            tried[hash_result] = collision
        print("no collision found")


if __name__ == "__main__":
    main()
