from Crypto.Random import random, get_random_bytes
from Crypto.Cipher import AES

KEY = get_random_bytes(16)
cipher = AES.new(KEY, AES.MODE_ECB)


def parse_url_data(url_data):
    return dict([kv.split('=') for kv in url_data.split('&')])


def profile_for(email):
    assert '&' not in email and '=' not in email, "Illegal email found"
    return f"email={email}&uid={random.randint(10000, 100000)}&role=user".encode('utf8')


def pad(data, size):
    padding_size = (size - (len(data) % size))
    return data + padding_size.to_bytes(1, 'little') * padding_size


def encrypt_profile(email):
    profile = pad(profile_for(email), len(KEY))
    return cipher.encrypt(profile)


def decrypt_profile(profile):
    raw_decrypted = cipher.decrypt(profile)
    if raw_decrypted[-1] < len(KEY):
        raw_decrypted = raw_decrypted[:-raw_decrypted[-1]]
    decrypted = raw_decrypted.decode('utf8')
    return parse_url_data(decrypted)


def main():
    first_profile = encrypt_profile("asaf@a.comadmin")
    second_profile = encrypt_profile("asaf@a.com")
    print(decrypt_profile(second_profile[:32] + first_profile[16:32] + first_profile[:16]))


if __name__ == "__main__":
    main()
