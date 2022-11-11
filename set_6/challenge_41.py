from Crypto.Util.number import getPrime


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


def to_bytes(i: int):
    return i.to_bytes((i.bit_length() + 7) // 8, 'little')


class RSA:
    e = 65537

    def __init__(self):
        while True:
            p = getPrime(512)
            q = getPrime(512)
            et = (p - 1) * (q - 1)
            if gcd(self.e, et) == 1:
                break
        self.n = p * q
        self._d = invmod(self.e, et)

    def encrypt(self, plain: bytes):
        return pow(plain, self.e, self.n)

    def decrypt(self, cipher: bytes):
        return pow(cipher, self._d, self.n)


def get_s(n):
    for i in range(2, 10000):
        if gcd(i, n) == 1:
            return i


def main():
    rsa = RSA()
    c = rsa.encrypt(int.from_bytes(b"This is a super secret message", 'little'))
    s = get_s(rsa.n)

    new_encrypted = (c * pow(s, rsa.e, rsa.n)) % rsa.n
    new_decrypted = (rsa.decrypt(new_encrypted) * invmod(s, rsa.n)) % rsa.n
    print(to_bytes(new_decrypted))


if __name__ == "__main__":
    main()
