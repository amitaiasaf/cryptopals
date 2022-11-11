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
    e = 3

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
        plain_number = int.from_bytes(plain, 'little')
        return to_bytes(pow(plain_number, self.e, self.n))

    def decrypt(self, cipher: bytes):
        cipher_number = int.from_bytes(cipher, 'little')
        return to_bytes(pow(cipher_number, self._d, self.n))


def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1


def main():
    ciphers = [RSA() for i in range(3)]

    plain = b"Asaf Amitai"
    encrypted = [int.from_bytes(cipher.encrypt(plain), 'little') for cipher in ciphers]

    m_s = [ciphers[1].n * ciphers[2].n, ciphers[0].n * ciphers[2].n, ciphers[0].n * ciphers[1].n]
    n_012 = ciphers[0].n * ciphers[1].n * ciphers[2].n

    result = sum([encrypted[i] * m_s[i] * invmod(m_s[i], ciphers[i].n) for i in range(3)]) % n_012
    print(to_bytes(nth_root(result, 3)))


if __name__ == "__main__":
    main()
