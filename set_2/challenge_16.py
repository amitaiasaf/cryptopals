from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_SIZE = 16
KEY = get_random_bytes(KEY_SIZE)
INITIAL_VALUE = get_random_bytes(KEY_SIZE)


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


CIPHER = AES_CBC(KEY, INITIAL_VALUE)


def create_cookies(user_data):
    assert ';' not in user_data and '=' not in user_data, "Invalid user data"
    return f"comment1=cooking%20MCs;userdata={user_data};comment2=%20like%20a%20pound%20of%20bacon".encode('utf8')


def create_encrypted_cookies(user_data):
    cookies = pad(create_cookies(user_data), KEY_SIZE)
    return CIPHER.encrypt(cookies)


def main():
    user_data = "\0" * KEY_SIZE * 2
    encrypted_cookies = create_encrypted_cookies(user_data)
    encrypted_cookies = encrypted_cookies[:KEY_SIZE * 2] + xor_with_key(
        b";role=admin;abc=", encrypted_cookies[KEY_SIZE * 2: KEY_SIZE * 3]) + encrypted_cookies[KEY_SIZE * 3:]
    print(CIPHER.decrypt(encrypted_cookies))


if __name__ == "__main__":
    main()
