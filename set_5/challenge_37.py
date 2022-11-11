

from Crypto.Random import get_random_bytes, random
import hashlib
import hmac

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
G = 2
K = 3

SALT = get_random_bytes(16)


def to_bytes(i: int):
    return i.to_bytes((i.bit_length() + 7) // 8, 'little')


class Server:
    PASSWORD = b"MyTopSecretPassword"

    def __init__(self):
        x = int.from_bytes(hashlib.sha256(SALT + self.PASSWORD).digest(), 'little')
        self._v = pow(G, x, N)
        self._b = random.randint(1, N - 1)
        self._B = K * self._v + pow(G, self._b, N)

    def get_public_key(self):
        return self._B

    def check_password(self, A, H):
        u = int.from_bytes(hashlib.sha256(to_bytes(A) + to_bytes(self._B)).digest(), 'little')
        s = pow(A * pow(self._v, u, N), self._b, N)
        return hmac.new(hashlib.sha256(to_bytes(s)).digest(), SALT, digestmod=hashlib.sha256).hexdigest() == H


class Client:

    def __init__(self, server: Server):
        self._a = random.randint(1, N - 1)
        self._A = 0
        self._server = server
        self._B = server.get_public_key()
        self._u = int.from_bytes(hashlib.sha256(to_bytes(self._A) + to_bytes(self._B)).digest(), 'little')

    def check_password(self, password):
        x = int.from_bytes(hashlib.sha256(SALT + password).digest(), 'little')
        s = 0
        h = hmac.new(hashlib.sha256(to_bytes(s)).digest(), SALT, digestmod=hashlib.sha256).hexdigest()
        return self._server.check_password(self._A, h)


def main():
    server = Server()
    client = Client(server)
    print(client.check_password(b"incorrect password"))
    print(client.check_password(Server.PASSWORD))


if __name__ == "__main__":
    main()
