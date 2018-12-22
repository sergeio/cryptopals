# -*- coding: utf-8 -*-
from crypto_set3 import split_into_chunks

# Note 1: All variables are unsigned 32-bit quantities and wrap modulo 232 when
#     calculating, except for ml, the message length, which is a 64-bit
#     quantity, and hh, the message digest, which is a 160-bit quantity.
# Note 2: All constants in this pseudo code are in big endian.  Within each
#     word, the most significant byte is stored in the leftmost byte position

def rotl32(value, count):
    # From https://en.wikipedia.org/wiki/Circular_shift
    assert count < 32
    return value << count | value >> (32-count)

def bitwise_not32(value):
    return 0xffffffff - value

def encode_as_chars(integer):
    """Turn 64-bit integer into 8 characters."""
    mask = 0xff
    ords = []
    assert integer >= 0
    while integer > 0:
        ords.append(int(integer & mask))
        integer = integer >> 8

    assert len(ords) <= 8
    ords += [0] * (8 - len(ords))

    ords = map(chr, ords)
    ords = list(reversed(ords))
    return ''.join(ords)

def ml_pad_message(message, length=None, faking_message=False):
    # ml = message length in bits (always a multiple of the number of bits in a
    # character).
    message_length = len(message) if not length else length

    # This is probably not correct for non-ascii messages
    ml = message_length * 8

    # append the bit '1' to the message e.g. by adding 0x80 if message length
    # is a multiple of 8 bits.
    message += '\x80'

    # append 0 ≤ k < 512 bits '0', such that the resulting message length in
    # bits is congruent to −64 ≡ 448 (mod 512)
    if faking_message:
        bits_to_append = 448 - (((message_length + 1) * 8) % 512)
    else:
        bits_to_append = 448 - ((len(message) * 8) % 512)
    message += '\x00' * (bits_to_append / 8)

    # append ml, the original message length, as a 64-bit big-endian integer.
    # Thus, the total length is a multiple of 512 bits.
    message += encode_as_chars(ml)
    return message

def sha1(message, state=None, length=None):
    if not state:
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
    else:
        h0, h1, h2, h3, h4 = state

    padded_message = ml_pad_message(message, length=length)

    # Process the message in successive 512-bit chunks:
    # break message into 512-bit chunks
    for chunk in split_into_chunks(padded_message, 512 / 8):
        # break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        words = split_into_chunks(chunk, 32 / 8)
        # convert string-encoded words into integers
        words = [int(w.encode('hex'), base=16) for w in words]
        words += [0 for _ in xrange(80 - 16)]

        # Extend the sixteen 32-bit words into eighty 32-bit words:
        # for i from 16 to 79
        #     w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
        for i in xrange(16, 80):
            words[i] = rotl32(
                words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16],
                1)

        # Initialize hash value for this chunk:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for i in xrange(80):
            if 0 <= i <= 19:
                f = (b & c) | (bitwise_not32(b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotl32(a, 5) + f + e + k + words[i]) & 0xffffffff
            e = d
            d = c
            c = rotl32(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    # Produce the final hash value (big-endian) as a 160-bit number:
    hh = (h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4
    return hh
