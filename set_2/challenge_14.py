from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
import base64
from collections import Counter

KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)

FLAG = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK"

CIPHER = AES.new(KEY, AES.MODE_ECB)


def pad(data, size):
    padding_size = (size - (len(data) % size))
    return data + padding_size.to_bytes(1, 'little') * padding_size


def encryption_oracle(data):
    data = pad(get_random_bytes(random.randint(0, 32)) + data + base64.b64decode(FLAG), len(KEY))
    return CIPHER.encrypt(data)


def get_block(data, block_num):
    return data[block_num * KEY_SIZE: (block_num + 1) * KEY_SIZE]


def encrypt_without_random(data):
    data = b"\xff" * KEY_SIZE * 2 + data
    counter = Counter()
    while True:
        encrypted_data = encryption_oracle(data)
        for i in range(3):
            if get_block(encrypted_data, i) == get_block(encrypted_data, i + 1):
                supposed = encrypted_data[(i + 2) * KEY_SIZE:]
                counter[supposed] += 1
                if counter[supposed] == 4:
                    return supposed


def decrypt_block(block_num, decrypted):
    for i in range(KEY_SIZE):
        padding = b"\0" * (KEY_SIZE - i - 1)
        cipher_to_compare = get_block(encrypt_without_random(padding), block_num)
        for j in range(256):
            if get_block(encrypt_without_random((padding + bytes(decrypted + [j]))[-KEY_SIZE:]), 0) == cipher_to_compare:
                decrypted.append(j)
                print(bytes(decrypted))
                break
        else:
            return decrypted
    return decrypted


def main():
    num_blocks = len(encrypt_without_random(b"")) // KEY_SIZE
    decrypted = []
    for i in range(num_blocks):
        decrypted = decrypt_block(i, decrypted)
    print(bytes(decrypted)[:-decrypted[-1]])
    assert base64.b64decode(FLAG) == bytes(decrypted)[:-decrypted[-1]]


if __name__ == "__main__":
    main()
