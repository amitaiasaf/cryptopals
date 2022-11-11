from Crypto.Cipher import AES
from Crypto.Random import random, get_random_bytes
import base64

KEY = get_random_bytes(16)

FLAG = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK"


def pad(data, size):
    padding_size = (size - (len(data) % size))
    return data + padding_size.to_bytes(1, 'little') * padding_size


def encryption_oracle(data):
    data = pad(data + base64.b64decode(FLAG), len(KEY))
    return AES.new(KEY, AES.MODE_CBC, b"\0" * 16).encrypt(data)


def get_oracle_key_size():
    for i in range(1, 1000000):
        encrypted_data = encryption_oracle(b"\0" * (2 * i))
        if encrypted_data[:i] == encrypted_data[i:2 * i]:
            return i


def decrypt_block(block_num, decrypted, key_size):
    for i in range(key_size):
        padding = b"\0" * (key_size - i - 1)
        cipher_to_compare = encryption_oracle(padding)[block_num * key_size:(block_num + 1) * key_size]
        for j in range(256):
            if cipher_to_compare == encryption_oracle((padding + bytes(decrypted + [j]))[-key_size:])[:key_size]:
                decrypted.append(j)
                break
    return decrypted


def main():
    key_size = get_oracle_key_size()
    num_blocks = len(encryption_oracle(b"")) // key_size
    decrypted = []
    for i in range(num_blocks):
        decrypted = decrypt_block(i, decrypted, key_size)
    print(bytes(decrypted)[:-decrypted[-1]])
    assert base64.b64decode(FLAG) == bytes(decrypted)[:-decrypted[-1]]


if __name__ == "__main__":
    main()
