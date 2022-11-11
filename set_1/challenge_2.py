import base64


def xor_strings(str1, str2):
    str1 = base64.b16decode(str1.upper())
    str2 = base64.b16decode(str2.upper())
    return base64.b16encode(bytes(map(lambda c1, c2: c1 ^ c2, str1, str2)))


print(xor_strings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
