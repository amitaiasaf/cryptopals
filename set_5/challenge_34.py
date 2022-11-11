from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import AES
import hashlib

BLOCK_SIZE = 16


def remove_padding(data: bytes):
    assert len(data) % BLOCK_SIZE == 0, "data is not padded to key size"
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


class DiffieHellmanSide:
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 5

    def __init__(self):
        self._a = random.randint(1, self.p - 1)
        self.public_key = pow(self.g, self._a, self.p)
        self._private_key = None

    def get_public_key(self):
        return self.public_key

    def set_private_key(self, another_public_key):
        self._private_key = pow(another_public_key, self._a, self.p)
        self._aes_key = hashlib.sha256(self._private_key.to_bytes(
            (self._private_key.bit_length() + 7) // 8, "little")).digest()
        self._iv = get_random_bytes(BLOCK_SIZE)
        self._cipher = AES.new(self._aes_key, AES.MODE_CBC, self._iv)

    def encrypt(self, message):
        return self._iv + self._cipher.encrypt(pad(message, BLOCK_SIZE))

    def decrypt(self, encrypted_message):
        iv = encrypted_message[:self._cipher.block_size]
        message_data = encrypted_message[self._cipher.block_size:]
        return remove_padding(AES.new(self._aes_key, AES.MODE_CBC, iv).decrypt(message_data))


class MITM:
    def __init__(self, alice: DiffieHellmanSide, bob: DiffieHellmanSide):
        self._alice = alice
        self._bob = bob
        self._bob.set_private_key(self._alice.p)
        self._alice.set_private_key(self._bob.p)
        self._key = 0
        self._aes_key = hashlib.sha256(self._key.to_bytes(
            (self._key.bit_length() + 7) // 8, "little")).digest()

    def send_encrypted_message_to_bob(self, encrypted_message):
        iv = encrypted_message[:BLOCK_SIZE]
        cipher = AES.new(hashlib.sha256(bytes()).digest(), AES.MODE_CBC, iv)
        print(remove_padding(cipher.decrypt(encrypted_message[BLOCK_SIZE:])))
        print(self._bob.decrypt(encrypted_message))


def main():
    alice = DiffieHellmanSide()
    bob = DiffieHellmanSide()
    mitm = MITM(alice, bob)
    message = b'hello world'
    encrypted_message = alice.encrypt(message)
    mitm.send_encrypted_message_to_bob(encrypted_message)


if __name__ == "__main__":
    main()
