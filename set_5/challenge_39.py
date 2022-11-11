from Crypto.Util.number import getPrime


def invmod(a, n):
    assert n > a and gcd(a, n) == 1
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
    e = 3

    def __init__(self):
        while True:
            p = getPrime(512)
            q = getPrime(512)
            et = (p - 1) * (q - 1)
            if gcd(self.e, et) == 1:
                break
        self._n = p * q
        self._d = invmod(self.e, et)

    def encrypt(self, plain: bytes):
        plain_number = int.from_bytes(plain, 'little')
        return to_bytes(pow(plain_number, self.e, self._n))

    def decrypt(self, cipher: bytes):
        cipher_number = int.from_bytes(cipher, 'little')
        return to_bytes(pow(cipher_number, self._d, self._n))


def main():
    cipher = RSA()

    plain = b"Asaf Amitai"
    encrypted = cipher.encrypt(plain)
    print(encrypted, cipher.decrypt(encrypted))


if __name__ == "__main__":
    main()
