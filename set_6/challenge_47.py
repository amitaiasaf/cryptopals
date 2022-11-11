from Crypto.Util.number import getPrime
import base64
import math
from Crypto.Random import get_random_bytes, random


def invmod(a, n):
    assert gcd(a, n) == 1
    if a > n:
        a = a % n
    old_r, r = n, a
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r % r
        old_t, t = t, old_t - q * t

    return (old_t + n) % n


def gcd(a, b):
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a


class RSA:
    e = 65537

    def __init__(self):
        while True:
            p = getPrime(128)
            q = getPrime(128)
            et = (p - 1) * (q - 1)
            if gcd(self.e, et) == 1:
                break
        self.n = p * q
        self._d = invmod(self.e, et)
        self.bit_length = self.n.bit_length()
        self.length = (self.bit_length + 7) // 8
        self.B = 2**(8*(self.length - 2))

    def encrypt(self, plain):
        return pow(plain, self.e, self.n)

    def decrypt(self, cipher):
        return pow(cipher, self._d, self.n)

    def to_bytes(self, i):
        return i.to_bytes(self.length, 'big')

    def pad_message(self, message):
        return b'\0\x02' + b'\xff'*(self.length - 3 - len(message)) + b'\0' + message

    @staticmethod
    def from_bytes(b):
        return int.from_bytes(b, 'big')

    def is_pkcs_conforming(self, cipher):
        return 2 * self.B <= self.decrypt(cipher) < 3 * self.B


def get_s0(rsa, c):
    while True:
        s0 = random.randint(1, rsa.n)
        if rsa.is_pkcs_conforming(c * rsa.encrypt(s0)):
            return s0


def get_next_s(rsa, c, s):
    while True:
        s += 1
        if rsa.is_pkcs_conforming(c * rsa.encrypt(s)):
            return s


def do_step_2c(rsa, c, M, prev_s):
    B = 2**(8*(rsa.length - 2))
    r = 2*(M[1]*prev_s - 2*B + rsa.n - 1) // rsa.n
    while True:
        for s in range((2*B + r*rsa.n + M[1] - 1)//M[1], (3*B + r*rsa.n + M[0] - 1)//M[0]):
            if rsa.is_pkcs_conforming(c*rsa.encrypt(s)):
                return s
        r += 1


def decrypt_message(rsa: RSA, c):
    B = 2**(8*(rsa.length - 2))

    M = [2*B, 3*B - 1]
    s0 = 1
    c0 = c * rsa.encrypt(s0)
    s = get_next_s(rsa, c, math.ceil(rsa.n / (3*B)))
    while M[0] < M[1]:
        r_min = (M[0]*s - 3*B+1 + rsa.n-1)//rsa.n
        M[0] = max(M[0], (2*B + r_min*rsa.n + s-1)//s)
        print(rsa.to_bytes(M[0]))
        # r_max = (M[1]*s - 2*B) // rsa.n
        r_max = r_min
        M[1] = min(M[1], (3*B-1 + r_max*rsa.n)//s)
        print(rsa.to_bytes(M[1]))
        s = do_step_2c(rsa, c, M, s)
    return M[0]


def main():
    rsa = RSA()
    message = rsa.from_bytes(rsa.pad_message(b'Message'))
    c = rsa.encrypt(message)
    assert rsa.is_pkcs_conforming(c)
    print(decrypt_message(rsa, c))


if __name__ == "__main__":
    main()
