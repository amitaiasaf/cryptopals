

from Crypto.Random import get_random_bytes, random
import hashlib
import hmac
import os

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
G = 2

SALT = get_random_bytes(16)

WORDS = map(str.strip, open(os.path.join(os.path.dirname(__file__), "data/challenge_38.txt")).read().splitlines())


def to_bytes(i: int):
    return i.to_bytes((i.bit_length() + 7) // 8, 'little')


class Server:

    def __init__(self):
        self._b = random.randint(1, N - 1)
        self._B = pow(G, self._b, N)

    def get_public_key(self):
        return self._B

    def check_password(self, A, H):
        for word in WORDS:
            x = int.from_bytes(hashlib.sha256(SALT + word.encode("utf8")).digest(), 'little')
            v = pow(G, x, N)
            u = int.from_bytes(hashlib.sha256(to_bytes(A) + to_bytes(self._B)).digest(), 'little')
            s = pow(A * pow(v, u, N), self._b, N)
            if hmac.new(hashlib.sha256(to_bytes(s)).digest(), SALT, digestmod=hashlib.sha256).hexdigest() == H:
                print("WORD is", word)
                break


class Client:

    PASSWORD = b"Abraham"

    def __init__(self, server: Server):
        self._a = random.randint(1, N - 1)
        self._A = pow(G, self._a, N)
        self._server = server
        self._B = server.get_public_key()
        self._u = int.from_bytes(hashlib.sha256(to_bytes(self._A) + to_bytes(self._B)).digest(), 'little')

    def check_password(self, password):
        x = int.from_bytes(hashlib.sha256(SALT + password).digest(), 'little')
        s = pow(self._B, self._a + self._u * x, N)
        h = hmac.new(hashlib.sha256(to_bytes(s)).digest(), SALT, digestmod=hashlib.sha256).hexdigest()
        return self._server.check_password(self._A, h)


def main():
    server = Server()
    client = Client(server)
    print(client.check_password(client.PASSWORD))


if __name__ == "__main__":
    main()
