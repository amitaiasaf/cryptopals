from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import string

KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)


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


CIPHER = AES_CBC(KEY, KEY)

VALID_CHARS = {ord(c) for c in string.printable}


def encrypt_message(message):
    print("KEY:", KEY)
    return CIPHER.encrypt(message)


def assert_message_is_valid(message):
    decrypted = CIPHER.decrypt(message)
    if not all(c in VALID_CHARS for c in decrypted):
        raise ValueError(decrypted)


def main():
    message = b'\0' * KEY_SIZE * 3
    encrypted = encrypt_message(message)
    try:
        assert_message_is_valid(encrypted[:KEY_SIZE] + b'\0' * KEY_SIZE + encrypted[:KEY_SIZE])
    except ValueError as e:
        decrypted = eval(str(e))
        print("Recovered key:", xor_with_key(decrypted[:KEY_SIZE], decrypted[2 * KEY_SIZE:]))


if __name__ == "__main__":
    main()
