from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
import base64

KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)
INITIAL_VALUE = get_random_bytes(KEY_SIZE)

FLAGS = [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
         b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
         b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
         b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
         b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
         b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
         b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
         b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
         b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
         b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93", ]


def remove_padding(data: bytes):
    assert len(data) % KEY_SIZE == 0, "data is not padded to key size"
    if data == b"":
        return data
    padding_size = data[-1]
    assert 0 != padding_size and bytes([padding_size] * padding_size) == data[-padding_size:], "Invalid padding"
    return data[:-padding_size]


def pad(data, size):
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


CIPHER = AES_CBC(KEY, INITIAL_VALUE)


def get_encrypted_flag():
    return CIPHER.encrypt(pad(base64.b64decode(random.choice(FLAGS)), KEY_SIZE))


def has_valid_padding(encrypted_data):
    decrypted = CIPHER.decrypt(encrypted_data)
    try:
        remove_padding(decrypted)
        return True
    except:
        return False


def get_block(data, block_num):
    return data[block_num * KEY_SIZE: (block_num + 1) * KEY_SIZE]


def decrypt_block(block_data, previous_block):
    xor_to_valid_padding = []
    for i in range(KEY_SIZE):
        xor_to_valid_padding = xor_with_key(bytes([i] * i),
                                            xor_with_key(xor_to_valid_padding, bytes([(i + 1) % 256] * i)))
        for j in range(256):
            padding = b"\0" * (KEY_SIZE - i - 1)
            xor_to_check = padding + bytes([j]) + xor_to_valid_padding
            if has_valid_padding(xor_with_key(xor_to_check, previous_block) + block_data):
                xor_to_check = padding[:-1] + b'\1' + bytes([j]) + xor_to_valid_padding
                if i != 0 or has_valid_padding(xor_with_key(xor_to_check, previous_block) + block_data):
                    xor_to_valid_padding = bytes([j]) + xor_to_valid_padding
                    break
    return xor_with_key(xor_to_valid_padding, bytes([KEY_SIZE] * KEY_SIZE))


def main():
    encrypted_flag = get_encrypted_flag()
    num_blocks = len(encrypted_flag) // KEY_SIZE
    xor_keys = INITIAL_VALUE + encrypted_flag[:-KEY_SIZE]
    decrypted = b""
    for i in range(num_blocks):
        decrypted += decrypt_block(get_block(encrypted_flag, i), get_block(xor_keys, i))
    print(remove_padding(decrypted))


if __name__ == "__main__":
    main()
