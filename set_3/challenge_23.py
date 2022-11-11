class MersenneTwister():
    w = 32
    n = 624
    m = 397
    r = 31
    a = 0x9908B0DF
    u = 11
    d = 0xFFFFFFFF
    s = 7
    b = 0x9D2C5680
    t = 15
    c = 0xEFC60000
    l = 18
    f = 1812433253

    LOWER_MASK = (1 << r) - 1
    UPPER_MASK = ((1 << w) - 1) & ~LOWER_MASK

    @staticmethod
    def uint(num):
        return num & ((1 << MersenneTwister.w) - 1)

    def __init__(self, seed):
        self.MT = [0 for i in range(self.n)]
        self.MT[0] = seed
        for i in range(1, self.n):
            self.MT[i] = self.uint(self.f * (self.MT[i-1] ^ (self.MT[i-1] >> (self.w-2))) + i)
        self.index = self.n

    def twist(self):
        for i in range(self.n):
            x = (self.MT[i] & self.UPPER_MASK) + (self.MT[(i + 1) % self.n] & self.LOWER_MASK)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a
            self.MT[i] = self.uint(self.MT[(i + self.m) % self.n] ^ xA)
        self.index = 0

    def __iter__(self):
        return self

    def __next__(self):
        if self.index >= self.n:
            self.twist()
        y = self.MT[self.index]
        self.index += 1

        y ^= (y >> self.u) & self.d
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)
        return self.uint(y)


def reverse_lshift(y, shift, mask, w):
    x = y & ((1 << shift) - 1)
    for i in range(shift, w):
        shift_mask = 1 << i
        x |= (bool(x & (1 << i - shift)) & bool(mask & shift_mask) ^ bool(y & shift_mask)) << i
    return MersenneTwister.uint(x)


def reverse_rshift(y, shift, mask, w):
    x = 0
    for i in range(w - 1, -1, -1):
        shift_mask = 1 << i
        x |= (bool(x & (1 << (i + shift))) & bool(mask & shift_mask) ^ bool(y & shift_mask)) << i
    return MersenneTwister.uint(x)


def clone_twister(twister: MersenneTwister):
    cloned = MersenneTwister(0)
    for i in range(MersenneTwister.n):
        y = next(twister)
        y = reverse_rshift(y, MersenneTwister.l, MersenneTwister.d, MersenneTwister.w)
        y = reverse_lshift(y, MersenneTwister.t, MersenneTwister.c, MersenneTwister.w)
        y = reverse_lshift(y, MersenneTwister.s, MersenneTwister.b, MersenneTwister.w)
        y = reverse_rshift(y, MersenneTwister.u, MersenneTwister.d, MersenneTwister.w)
        cloned.MT[i] = MersenneTwister.uint(y)
    return cloned


def main():
    twister = MersenneTwister(17)
    cloned = clone_twister(twister)
    for i in range(1000):
        print(next(twister), next(cloned))


if __name__ == "__main__":
    main()
