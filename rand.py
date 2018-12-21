def lowest_x_bits(x, num):
    return ((2 ** x) - 1) & num

def mask_highest_x_bits(x, num):
    """Get the first x bits of 32-bit inteter `num`, include 0s."""
    assert num < 0xFFFFFFFF
    return (num >> (32 - x)) << (32 - x)

class Rand:

    (w, n, m, r) = (32, 624, 397, 31)
    a = 0x9908B0DF
    (u, d) = (11, 0xFFFFFFFF)
    (s, b) = (7, 0x9D2C5680)
    (t, c) = (15, 0xEFC60000)
    l = 18
    f = 1812433253

    lower_mask = (1 << r) - 1
    upper_mask = lowest_x_bits(w, (not lower_mask))

    def __init__(self, seed=5489):
        self.mt = range(self.n)
        self.index = self.n + 1
        self.seed_mt(seed)

    def seed_mt(self, seed):
        self.index = self.n
        self.mt[0] = seed
        for i in xrange(1, self.n):
            mathmath = self.f * (
                self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i
            self.mt[i] = lowest_x_bits(self.w, mathmath)

    def splice(self, state_list):
        self.mt = state_list
        self.twist()

    def extract_number(self):
        # print self.index
        if self.index >= self.n:
            if self.index > self.n:
                raise Exception("Generator was never seeded")
            self.twist()

        y = self.mt[self.index]
        y = self.temper(y)
        self.index = self.index + 1
        return lowest_x_bits(self.w, y)

    def temper(self, y):
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        return y

    def untemper(self, y):
        y = y ^ (y >> self.l)
        y = y ^ ((y << self.t) & self.c)

        recovered = lowest_x_bits(self.s, y)
        for _ in xrange((self.w // self.s)):
            recovered = y ^ (recovered << self.s) & self.b
        y = recovered

        recovered = mask_highest_x_bits(self.u, y)
        for _ in xrange(self.w // self.u):
            recovered = y ^ (recovered >> self.u)
        y = recovered

        return y

    def twist(self):
        for i in xrange(self.n):
            self.x = (self.mt[i] & self.upper_mask) + (
                self.mt[(i + 1) % self.n] & self.lower_mask)
            xA = self.x >> 1
            if (self.x % 2) != 0:
                xA = xA ^ self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0

    def rand(self):
        return self.extract_number() / float((2 ** self.w) - 1)

    def randint(self, *args):
        assert args
        if len(args) == 1:
            [max_] = args
            assert max_ > 0
            min_ = 0
        elif len(args) == 2:
            [min_, max_] = args
            assert min_ < max_
        else:
            raise Exception('Too many args')
        x = self.rand() * (max_ - min_)
        return int(round(x - .5) + min_)
