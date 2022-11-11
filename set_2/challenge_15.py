KEY_SIZE = 16


def remove_padding(data: bytes):
    assert len(data) % KEY_SIZE == 0, "data is not padded to key size"
    if data == b"":
        return data
    padding_size = data[-1]
    if padding_size >= KEY_SIZE:
        return data
    assert bytes([padding_size] * padding_size) == data[-padding_size:], "Invalid padding"
    return data[:-padding_size]


def main():
    print(remove_padding(b"ICE ICE BABY\x05\x05\x05\x04"))


if __name__ == "__main__":
    main()
