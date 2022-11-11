import struct
from Crypto.Random import get_random_bytes
import io


class MD4:
    """An implementation of the MD4 hash algorithm."""

    width = 32
    mask = 0xFFFFFFFF

    # Unlike, say, SHA-1, MD4 uses little-endian. Fascinating!

    def __init__(self, msg=None, h=None, previous_len=None):
        """:param ByteString msg: The message to be hashed."""
        if msg is None:
            msg = b""

        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        if h is not None:
            self.h = h
        self.msg = msg

        # Pre-processing: Total length is a multiple of 512 bits.
        if previous_len is None:
            ml = len(msg) * 8
        else:
            ml = (len(msg) + previous_len) * 8
        msg += b"\x80"
        msg += b"\x00" * (-(len(msg) + 8) % 64)
        msg += struct.pack("<Q", ml)

        # Process the message in successive 512-bit chunks.
        self._process([msg[i: i + 64] for i in range(0, len(msg), 64)])

    def __repr__(self):
        if self.msg:
            return f"{self.__class__.__name__}({self.msg:s})"
        return f"{self.__class__.__name__}()"

    def __str__(self):
        return self.hexdigest()

    def __eq__(self, other):
        return self.h == other.h

    def bytes(self):
        """:return: The final hash value as a `bytes` object."""
        return struct.pack("<4L", *self.h)

    def hexbytes(self):
        """:return: The final hash value as hexbytes."""
        return self.hexdigest().encode

    def hexdigest(self):
        """:return: The final hash value as a hexstring."""
        return "".join(f"{value:02x}" for value in self.bytes())

    def _process(self, chunks):
        for chunk in chunks:
            X, h = list(struct.unpack("<16I", chunk)), self.h.copy()

            # Round 1.
            Xi = [3, 7, 11, 19]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n, Xi[n % 4]
                hn = h[i] + MD4.F(h[j], h[k], h[l]) + X[K]
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 2.
            Xi = [3, 5, 9, 13]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = n % 4 * 4 + n // 4, Xi[n % 4]
                hn = h[i] + MD4.G(h[j], h[k], h[l]) + X[K] + 0x5A827999
                h[i] = MD4.lrot(hn & MD4.mask, S)

            # Round 3.
            Xi = [3, 9, 11, 15]
            Ki = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for n in range(16):
                i, j, k, l = map(lambda x: x % 4, range(-n, -n + 4))
                K, S = Ki[n], Xi[n % 4]
                hn = h[i] + MD4.H(h[j], h[k], h[l]) + X[K] + 0x6ED9EBA1
                h[i] = MD4.lrot(hn & MD4.mask, S)

            self.h = [((v + n) & MD4.mask) for v, n in zip(self.h, h)]

    @staticmethod
    def F(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def H(x, y, z):
        return x ^ y ^ z

    @staticmethod
    def lrot(value, n):
        lbits, rbits = (value << n) & MD4.mask, value >> (MD4.width - n)
        return lbits | rbits


SECRET_KEY = get_random_bytes(16)


def get_message_signature(message):
    return MD4(SECRET_KEY + message).hexdigest()


def verify_message_signature(message, signature):
    assert get_message_signature(message) == signature.hexdigest()


def pad_message(message, key_size):
    message_len = len(message) + key_size
    # append the bit '1' to the message
    message += b'\x80'

    # append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
    # is congruent to 56 (mod 64)
    message += b'\x00' * (-(message_len + 9) % 64)

    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    message_bit_length = message_len * 8
    message += struct.pack(b'<Q', message_bit_length)
    return message


def main():
    message = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    signature = get_message_signature(message)
    new_message = pad_message(message, len(SECRET_KEY)) + b";admin=true"
    h = [struct.unpack("<I", bytes.fromhex(signature[i:i+8]))[0] for i in range(0, len(signature), 8)]
    new_signature = MD4(b";admin=true", h, len(pad_message(message, len(SECRET_KEY))) + len(SECRET_KEY))
    verify_message_signature(new_message, new_signature)


if __name__ == "__main__":
    main()
