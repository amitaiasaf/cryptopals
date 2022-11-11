import base64
import string

ENCRYPTED_TEXT = base64.b16decode(b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".upper())


def is_allowed_char(c):
    return c in bytes(string.printable, "ascii")


def decryption_score(s):
    return all((is_allowed_char(c) for c in s)) and s.count(b" ")


def decypher(s):
    candidates = {}

    for i in range(255):
        candidates[i] = (bytes(map(lambda c:  c ^ i, s)))

    ret = max(candidates.values(), key=decryption_score)
    return ret, decryption_score(ret)


print(decypher(ENCRYPTED_TEXT))
