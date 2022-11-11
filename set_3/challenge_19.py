import base64
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from collections import Counter


def xor_with_key(s, key):
    return bytes(map(lambda i, c: c ^ key[i % len(key)], range(len(s)), s))


class AES_CTR:
    def __init__(self, key, nonce):
        self._aes = AES.new(key, AES.MODE_ECB)
        self._key = key
        self._nonce = nonce

    def encrypt(self, data):
        result = []
        for i in range(len(data)):
            block = data[i * len(self._key):(i + 1) * len(self._key)]
            cur_key = self._aes.encrypt(struct.pack("<QQ", self._nonce, i))
            result.append(xor_with_key(block, cur_key))

        return b"".join(result)

    def decrypt(self, data):
        return self.encrypt(data)


KEY = get_random_bytes(16)
CIPHER = AES_CTR(KEY, 0)

TEXTS = [
    b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
    b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
    b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
    b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
    b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
    b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
    b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
    b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
    b"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
    b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
    b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
    b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
    b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
    b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
    b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
    b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
    b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
    b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
    b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
    b"U2hlIHJvZGUgdG8gaGFycmllcnM/",
    b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
    b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
    b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
    b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
    b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
    b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
    b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
    b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
    b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
    b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
    b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
    b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
    b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
    b"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
    b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
    b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
    b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
]


def choose_char(possible_chars):
    if len(possible_chars) == 1:
        return bytes(possible_chars)
    if len(possible_chars) > 5:
        return b' '
    return b'?'


def main():
    encrypted_texts = list(map(lambda t: CIPHER.encrypt(base64.b64decode(t)), TEXTS))
    possible_chars = []
    for i in range(len(encrypted_texts)):
        possible_chars.append([set() for j in range(len(encrypted_texts[i]))])
        for text in encrypted_texts:
            if text == encrypted_texts[i]:
                continue
            xored = xor_with_key(encrypted_texts[i], text)
            for j, c in enumerate(xored):
                if chr(c).isupper() and chr(c).isascii():
                    possible_chars[i][j].add(c ^ 0x20)

    # Some corrections from previous runs
    possible_chars[-2][0] = {ord('T')}
    possible_chars[1][10] = {ord('h')}
    possible_chars[-3][22] = {ord('g')}
    possible_chars[2][25] = {ord('g')}
    possible_chars[-7][27] = {ord('r')}

    for i in range(len(encrypted_texts)):
        decrypted = []
        for k, c in enumerate(encrypted_texts[i]):
            for j in range(len(encrypted_texts)):
                if len(possible_chars[j]) > k:
                    if len(possible_chars[j][k]) == 1:
                        decrypted.append(list(possible_chars[j][k])[0] ^ c ^ encrypted_texts[j][k])
                        break
            else:
                decrypted.append(ord('?'))
        print("".join(map(chr, decrypted)))


if __name__ == "__main__":
    main()
