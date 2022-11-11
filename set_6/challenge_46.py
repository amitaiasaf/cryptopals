from Crypto.Util.number import getPrime
import base64


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
    return i.to_bytes((i.bit_length() + 7) // 8, 'big')


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

    def encrypt(self, plain):
        return pow(plain, self.e, self.n)

    def decrypt(self, cipher):
        return pow(cipher, self._d, self.n)

    def is_even(self, cipher):
        return self.decrypt(cipher) % 2 == 0


def binary_search(cipher: int, rsa: RSA):
    upper_bound = rsa.n
    lower_bound = 0
    is_even = rsa.is_even(cipher)
    while upper_bound != lower_bound:
        cipher = (cipher * rsa.encrypt(2)) % rsa.n
        if rsa.is_even(cipher):
            upper_bound = (upper_bound + lower_bound) // 2
            print(to_bytes(upper_bound))
        else:
            lower_bound = (upper_bound + lower_bound + 1) // 2
    return upper_bound


def main():
    rsa = RSA()
    c = rsa.encrypt(int.from_bytes(base64.b64decode(
        b"VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="), 'big'))
    print(to_bytes(binary_search(c, rsa)))


if __name__ == "__main__":
    main()
