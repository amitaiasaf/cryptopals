
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


def main():
    my_random = MersenneTwister(7)
    for r, i in zip(my_random, range(10)):
        print(r)


if __name__ == "__main__":
    main()
