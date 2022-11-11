from Crypto.Random import random
import hashlib

MESSAGE = b"""For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"""

assert hashlib.sha1(MESSAGE).hexdigest() == 'd2d0714f014a9784047eaeccf956520045c45265'


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


class DSA:
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

    def __init__(self):
        self._x = random.randint(1, self.q - 1)
        self._y = pow(self.g, self._x, self.p)

    def sign(self, message):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            if 0 == r:
                continue
            s = invmod(k, self.q) * (self._x * r + int.from_bytes(hashlib.sha1(message).digest(), 'big')) % self.q
            if 0 != s:
                return r, s

    def verify(self, message, r, s):
        assert 0 < r < self.q and 0 < s < self.q
        w = invmod(s, self.q)
        u1 = (int.from_bytes(hashlib.sha1(message).digest(), 'big') * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.g, u1, self.p) * pow(self._y, u2, self.p)) % self.p) % self.q
        assert r == v

    def recover_x_from_k(self, r, s, k, message):
        return (invmod(r, self.q) * (s * k - int.from_bytes(hashlib.sha1(message).digest(), 'big'))) % self.q


ORIGINAL_SIGNATURE = (548099063082341131477253921760299949438196259240,
                      857042759984254168557880549501802188789837994940)


def main():
    signer = DSA()
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    for k in range(2**16):
        try:
            x = signer.recover_x_from_k(*ORIGINAL_SIGNATURE, k, MESSAGE)
            if pow(signer.g, x, signer.p) == y:
                print(k, x, hashlib.sha1(hex(x)[2:].encode('ascii')).hexdigest())
                break
        except:
            continue


if __name__ == "__main__":
    main()
