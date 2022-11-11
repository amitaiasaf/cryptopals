import requests
import time

data = "AsafAmitai"

known = b''


def get_time(signature):
    t = time.time()
    requests.get(f"http://127.0.0.1:8000?file={data}&signature={signature}")
    return time.time() - t


for i in range(20):
    times = {j: sum(get_time((known + bytes([j]) + b'\0' * (20 - 1 - len(known))).hex())
                    for k in range(10)) for j in range(256)}
    known += bytes([max(times.keys(), key=lambda j: times[j])])
    print(known.hex())

print(known.hex())
