import base64
import operator
import os
import collections
from PIL import Image

DATA_PATH = os.path.join(os.path.dirname(__file__), "data/challenge_8.txt")


def edit_distance(s1, s2):
    xored = map(operator.xor, s1, s2)
    return bin(int.from_bytes(xored, byteorder='big')).count("1")


distances = {}
unique_blocks = {}

with open(DATA_PATH, "rb") as f:
    for line in f:
        decoded_line = base64.b16decode(line.strip().upper())
        distances[decoded_line] = edit_distance(decoded_line[:64], decoded_line[64:128])
        unique_blocks[decoded_line] = len(collections.Counter([decoded_line[i: i + 16]
                                                               for i in range(0, len(decoded_line), 16)]))

ecb = min(unique_blocks, key=lambda x: distances[x])
print(collections.Counter(unique_blocks.values()), unique_blocks[ecb])
