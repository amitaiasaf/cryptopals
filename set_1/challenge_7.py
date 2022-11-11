from Crypto.Cipher import AES
import base64
import os

DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_7.txt")

data = base64.b64decode(open(DATA_PATH, "rb").read())
aes = AES.new(b"YELLOW SUBMARINE", AES.MODE_ECB)

print(aes.decrypt(data))
