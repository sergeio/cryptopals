def lowest_x_bits(x, num):
    return ((2 ** x) - 1) & num

class Rand:

    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    mt = range(n)
    index = n + 1
    lower_mask = (1 << r) - 1
    upper_mask = lowest_x_bits(w, (not lower_mask))

    def __init__(self, seed=5489):
        self.seed_mt(seed)

    def seed_mt(self, seed):
        print seed
        self.index = self.n
        self.mt[0] = seed
        for i in xrange(self.n):
            mathmath = self.f * (
                self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i
            self.mt[i] = lowest_x_bits(self.w, mathmath)

    def extract_number(self):
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")
            self.twist()

        self.y = self.mt[self.index]
        self.y = self.y ^ ((self.y >> self.u) & self.d)
        self.y = self.y ^ ((self.y << self.s) & self.b)
        self.y = self.y ^ ((self.y << self.t) & self.c)
        self.y = self.y ^ (self.y >> self.l)

        self.index = self.index + 1
        return lowest_x_bits(self.w, self.y)

    def twist(self):
        for i in xrange(self.n):
            self.x = (self.mt[i] & self.upper_mask) + (
                self.mt[(i + 1) % self.n] & self.lower_mask)
            xA = self.x >> 1
            if (self.x % 2) != 0:
                xA = xA ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0

    def randint(self, min_=None, max_=None):
        if max_:
            assert min_ < max_
        assert not (min_ and not max_)
        extracted = self.extract_number()
        if max_:
            extracted %= max_
            if min_:
                shrink_factor = (max_ - min_) / float(max_)
                extracted = int(round(extracted * shrink_factor) + min_)

        return extracted

