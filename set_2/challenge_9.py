def pad(data, size):
    return data + (size - len(data)).to_bytes(1, 'little') * (size - len(data))


print(pad(b"YELLOW SUBMARINE", 20))
