from Crypto.Util.number import getPrime
import hashlib


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
        return pow(plain, self.e, self.n)

    def decrypt(self, cipher: bytes):
        return pow(cipher, self._d, self.n)


class RSADigitalSignature(RSA):
    def __init__(self):
        super().__init__()

    def sign(self, message):
        padded_message = int.from_bytes(b'\0\x01' + b'\xff' * 100 + b'\0' + message, 'big')
        return self.decrypt(padded_message)

    def verify(self, message, signature):
        signature_bytes = to_bytes(self.encrypt(signature))
        assert signature_bytes.startswith(b'\x01')
        hash_start_index = signature_bytes.find(b'\0', 1)
        assert b'\xff' * (hash_start_index - 1) == signature_bytes[1:hash_start_index]
        assert message == signature_bytes[hash_start_index + 1:]


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


def forge_signature(message):
    to_sign = int.from_bytes(b'\x01\xff\0' + message + b'\0' * len(message) * 4, 'big')
    root = nth_root(to_sign, 3) + 1
    forged_message = to_bytes(root ** 3)[3:]
    print("forged message to sign:", forged_message)
    return forged_message, root


def main():
    signer = RSADigitalSignature()
    message = b'I Forged a message!'
    legit_signature = signer.sign(message)
    signer.verify(message, legit_signature)
    signer.verify(*forge_signature(message))


if __name__ == "__main__":
    main()
