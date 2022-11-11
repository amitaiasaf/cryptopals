import base64

PLAIN_TEXT = b"""Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"""

CIPHER = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
KEY = b"ICE"


def xor_with_key(s, key):
    return base64.b16encode(bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s))).lower()


assert xor_with_key(PLAIN_TEXT, KEY) == CIPHER
