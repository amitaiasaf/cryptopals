from Crypto.Random import random
import hashlib
import os
import itertools

DATA_PATH = os.path.dirname(__file__) + "/data/challenge_44.txt"


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
    # g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    # g = 0
    g = p + 1

    def __init__(self):
        self._x = random.randint(1, self.q - 1)
        self._y = pow(self.g, self._x, self.p)

    def sign(self, message):
        while True:
            k = random.randint(1, self.q - 1)
            r = pow(self.g, k, self.p) % self.q
            # if 0 == r:
            #     continue
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


def get_line_data(f):
    line = f.readline()
    return line[line.find(' ') + 1:].replace('\n', '')


def get_data():
    msgs = {}
    with open(DATA_PATH, "r") as f:
        while True:
            try:
                msg = get_line_data(f)
                s = int(get_line_data(f))
                r = int(get_line_data(f))
                m = int(get_line_data(f), 16)
                assert int(hashlib.sha1(msg.encode('ascii')).hexdigest(), 16) == m
                msgs[m] = (r, s, msg)
            except:
                return msgs


def main():
    signer = DSA()
    message = b"Hello, world"
    z = random.randint(1, signer.q - 1)
    r = pow(signer._y, z, signer.p) % signer.q
    s = invmod(z, signer.q) * r
    signer.verify(message, r, s)


if __name__ == "__main__":
    main()
