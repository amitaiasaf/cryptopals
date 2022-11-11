

from Crypto.Cipher import AES
import struct
import base64

SECRET = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="


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


def main():
    cipher = AES_CTR(b"YELLOW SUBMARINE", 0)
    print(cipher.decrypt(base64.b64decode(SECRET)))


if __name__ == "__main__":
    main()
