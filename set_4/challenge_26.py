from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes, random
import struct

KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)
NONCE = random.getrandbits(64)


def pad(data, size):
    padding_size = (size - (len(data) % size))
    return data + padding_size.to_bytes(1, 'little') * padding_size


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


CIPHER = AES_CTR(KEY, NONCE)


def create_cookies(user_data):
    assert ';' not in user_data and '=' not in user_data, "Invalid user data"
    return f"comment1=cooking%20MCs;userdata={user_data};comment2=%20like%20a%20pound%20of%20bacon".encode('utf8')


def create_encrypted_cookies(user_data):
    cookies = pad(create_cookies(user_data), KEY_SIZE)
    return CIPHER.encrypt(cookies)


def main():
    user_data = "\0" * KEY_SIZE
    encrypted_cookies = create_encrypted_cookies(user_data)
    encrypted_cookies = encrypted_cookies[:KEY_SIZE * 2] + xor_with_key(
        b"abcde;role=admin", encrypted_cookies[KEY_SIZE * 2: KEY_SIZE * 3]) + encrypted_cookies[KEY_SIZE * 3:]
    print(CIPHER.decrypt(encrypted_cookies))


if __name__ == "__main__":
    main()
