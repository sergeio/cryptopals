from Crypto.Cipher import AES
import base64
import binascii
import collections
import itertools
import operator
import random
import string

import constants
import cosine_similarity


def hex_to_b64(hex_):
    return base64.b64encode(binascii.unhexlify(hex_))

def xor_bin(bin1, bin2):
    bytes1, bytes2 = map(bytearray, (bin1, bin2))
    xored = [bytes1[i] ^ bytes2[i % len(bytes2)] for i in xrange(len(bytes1))]
    return bytearray(xored)

def xor_hex(hex1, hex2):
    if len(hex1) < len(hex2):
        hex1, hex2 = hex2, hex1

    [bin1, bin2] = map(binascii.unhexlify, (hex1, hex2))

    return binascii.hexlify(xor_bin(bin1, bin2))

def letter_frequency(text):
    frequencies = collections.defaultdict(float)
    length = len(text)
    for char in text:
        frequencies[char] += 1.0 / length

    return frequencies

def english_score(text):
    """How closely does `text` resemble english?"""
    text_freqs = letter_frequency(text)
    english_freqs = letter_frequency(constants.long_str)
    all_chars = list(set(text_freqs).union(set(english_freqs)))

    text_freqs = [text_freqs.get(word, 0) for word in all_chars]
    english_freqs = [english_freqs.get(word, 0) for word in all_chars]

    return cosine_similarity.similarity(text_freqs, english_freqs)

def break_single_character_xor(text):
    """Break the single-character-xor-encrypted hex-encoded `text`"""
    bins = [(binascii.unhexlify(xor_hex(text, binascii.hexlify(char))), char)
            for char in string.printable]
    return max((english_score(b), b, char) for b, char in bins)

def challenge_3():
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    return break_single_character_xor(s)

def challenge_4():
    lines = []
    with open('4.txt', 'r') as f:
        lines = f.readlines()

    lines = map(lambda l: l.strip(), lines)
    return max(map(break_single_character_xor, lines))

def challenge_5():
    s = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    return binascii.hexlify(xor_bin(s, "ICE"))

def count_bin_ones(byte_array):
    """Count number of ones in binary representation of byte_array"""
    num_ones = 0
    for bin in byte_array:
        while bin != 0:
            if bin & 1:
                num_ones += 1
            bin = bin >> 1
    return num_ones

def hamming_distance(text1, text2):
    """Number of differing bits between texts"""
    bin_arr = xor_bin(text1, text2)
    return count_bin_ones(bin_arr)

def split_into_chunks(text, length):
    split = 0
    chunks = []
    while split < len(text):
        chunks.append(text[split:split + length])
        split += length
    return chunks

def challenge_6():
    with open('6.txt', 'r') as f:
        lines = f.readlines()

    lines = [l.strip() for l in lines]
    encoded = ''.join(lines)
    text = base64.b64decode(encoded)
    distance_stats = []
    for KEYSIZE in xrange(2, 41):
        chunks = [text[i * KEYSIZE: (i+1) * KEYSIZE] for i in xrange(10)]
        adj_dists = [hamming_distance(chunks[i], chunks[i+1]) / float(KEYSIZE)
                     for i in xrange(9)]
        distance_stats.append((sum(adj_dists) / len(adj_dists), KEYSIZE))
    probable_keysize = sorted(distance_stats)[0][1]

    chunks = split_into_chunks(text, probable_keysize)
    transposed = zip(*chunks)
    passcode = ''
    for t in transposed:
        t = binascii.hexlify(''.join(t))
        passcode += break_single_character_xor(t)[2]
    return passcode

def read_in_file(filename, b64decode=False):
    with open(filename, 'r') as f:
        lines = [l.strip() for l in f.readlines()]
    value = ''.join(lines)
    if b64decode:
        value = base64.b64decode(value)
    return value

def aes_ecb_decrypt(bytes, key):
    ciph = AES.new(key, AES.MODE_ECB)
    return ciph.decrypt(bytes)

def aes_ecb_encrypt(bytes, key):
    ciph = AES.new(key, AES.MODE_ECB)
    return ciph.encrypt(bytes)

def aes_cbc_decrypt(bytes, key, iv):
    encrypted_chunks = split_into_chunks(bytes, len(key))
    plaintext_chunks = []
    for i, chunk in enumerate(encrypted_chunks):
        intermediate = aes_ecb_decrypt(chunk, key)
        if plaintext_chunks:
            new_chunk = xor_bin(intermediate, encrypted_chunks[i - 1])
        else:
            new_chunk = xor_bin(intermediate, iv)
        plaintext_chunks.append(str(new_chunk))
    return ''.join(plaintext_chunks)

def aes_cbc_encrypt(bytes, key, iv):
    plaintext_chunks = split_into_chunks(bytes, len(key))
    encrypted_chunks = []
    for i, chunk in enumerate(plaintext_chunks):
        if encrypted_chunks:
            intermediate = xor_bin(chunk, encrypted_chunks[i - 1])
        else:
            intermediate = xor_bin(chunk, iv)
        new_chunk = aes_ecb_encrypt(str(intermediate), key)
        encrypted_chunks.append(new_chunk)
    return ''.join(encrypted_chunks)

def challenge_7():
    bytes = read_in_file('7.txt', b64decode=True)
    return aes_ecb_decrypt(bytes, 'YELLOW SUBMARINE')

def challenge_8():
    with open('8.txt', 'r') as f:
        lines = [l.strip() for l in f.readlines()]
    # binascii.unhexlify(lines)
    line_chunks_list = [split_into_chunks(l, 16) for l in lines]
    unique_chunks = [
        (len(set(chunks)), i) for i, chunks in enumerate(line_chunks_list)]
    return sorted(unique_chunks)

def challenge_10():
    bytes = read_in_file('10.txt', b64decode=True)
    return aes_cbc_decrypt(bytes, 'YELLOW SUBMARINE', '\x00'*16)

def pkcs7_padding(text, blocksize):
    chars_needed = blocksize - (len(text) % blocksize)
    return text + ('\x04' * chars_needed)

def make_random_aes_key(length=16):
    return ''.join(chr(random.randint(0, 128)) for _ in xrange(length))

def aes_unknown_mode_encrypt(plaintext):
    """Encrypt with cbc or ecb modes randomly"""
    iv = make_random_aes_key()
    key = make_random_aes_key()
    prepend = make_random_aes_key(length=random.randint(5, 11))
    append = make_random_aes_key(length=random.randint(5, 11))
    to_encrypt = pkcs7_padding(prepend + plaintext + append, len(key))
    if random.choice(('ECB', 'CBC')) == 'CBC':
        print 'encrypting in CBC'
        encrypted = aes_cbc_encrypt(to_encrypt, key, iv)
    else:
        print 'encrypting in ECB'
        encrypted = aes_ecb_encrypt(to_encrypt, key)
    return encrypted

def detect_aes_block_mode(plaintext, unknown_mode_encryptor):
    """Encrypts plaintext and guesses block mode"""
    plaintext = '\x00'*(16*8) + plaintext
    encrypted = unknown_mode_encryptor(plaintext)
    ECB = False
    for prepend in xrange(5):
        chunks = split_into_chunks(encrypted[prepend:], 16)
        if len(set(chunks)) < len(chunks):
            ECB = True
    return 'ECB' if ECB else 'CBC'

KEY1 = ''
def aes_ecb_random_key_encrypt(plaintext):
    global KEY1
    if not KEY1:
        KEY1 = make_random_aes_key()
    # secret string we're guessing
    append = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    to_encrypt = pkcs7_padding(plaintext + append, len(KEY1))
    return aes_ecb_encrypt(to_encrypt, KEY1)

KEY2 = ''
PREFIX = ''
def aes_ecb_random_key_encrypt_with_random_prefix(plaintext):
    global KEY2, PREFIX
    if not KEY2:
        KEY2 = make_random_aes_key()
    if not PREFIX:
        PREFIX = make_random_aes_key(length=random.randint(5, 60))
    # secret string we're guessing
    secret = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    to_encrypt = pkcs7_padding(PREFIX + plaintext + secret, len(KEY2))
    return aes_ecb_encrypt(to_encrypt, KEY2)


def challenge12():
    enc = aes_ecb_random_key_encrypt
    return break_oracle(enc)

def break_oracle(enc):
    # Detect block size:
    encrypted = enc('')
    original_length = len(encrypted)
    i = 1
    while len(encrypted) == original_length:
        encrypted = enc('A' * i)
        i += 1

    new_length = len(encrypted)
    j = i
    while len(encrypted) == new_length:
        encrypted = enc('A' * j)
        j += 1
    block_size = j - i

    assert detect_aes_block_mode('', enc) == 'ECB'

    recovered_plaintext = ''
    for num_blocks in xrange(1, len(enc('')) / block_size + 1):
        for i in reversed(range(block_size)):
            rainbow = {}
            prepend = 'A' * i
            chars_to_match = num_blocks * block_size
            for c in itertools.imap(chr, xrange(256)):
                match = enc(prepend + recovered_plaintext + c)[:chars_to_match]
                rainbow[match] = c

            block = enc(prepend)[:chars_to_match]
            recovered_plaintext += rainbow[block]
    return recovered_plaintext

def parse_params(param_string):
    """Turn foo=bar&baz=qux&zap=zazzle into a dict"""
    data = {}
    for pair in param_string.split('&'):
        k, v = pair.split('=')
        data[k] = v
    return data

def profile_for(email):
    email = email.replace('&', '')
    email = email.replace('=', '')
    data = {'email': email, 'uid': random.randint(0,10), 'role': 'user'}
    return '&'.join(['%s=%s' % (k, v) for k, v in data.iteritems()])

def make_encrypted_profile():
    profile = profile_for('userman@domain.com')
    key = make_random_aes_key()
    encrypted = aes_ecb_encrypt(pkcs7_padding(profile, len(key)), key)
    decrypted = aes_ecb_decrypt(encrypted, key)
    decrypted = decrypted.strip('\x04')
    return parse_params(decrypted)

def challenge14():
    enc = aes_ecb_random_key_encrypt_with_random_prefix
    # Detect block size:
    encrypted = enc('')
    original_length = len(encrypted)
    i = 1
    while len(encrypted) == original_length:
        encrypted = enc('A' * i)
        i += 1

    new_length = len(encrypted)
    j = i
    while len(encrypted) == new_length:
        encrypted = enc('A' * j)
        j += 1
    block_size = j - i

    assert detect_aes_block_mode('', enc) == 'ECB'

    # find first nonrandom block
    encrypted = enc('')
    chunks1 = split_into_chunks(encrypted, block_size)
    encrypted = enc('A')
    chunks2 = split_into_chunks(encrypted, block_size)
    injection_block_index = 9e99
    prev_injection_block = None
    for i, (c1, c2) in enumerate(zip(chunks1, chunks2)):
        if c1 != c2:
            injection_block_index = i
            prev_injection_block = chunks2[i]
            break

    # How much padding is needed to force the secret to begin at block start?
    required_padding = 0
    for i in xrange(2, block_size + 2):
        encrypted = enc('A' * i)
        chunks = split_into_chunks(encrypted, block_size)
        injection_block = chunks[injection_block_index]
        if injection_block == prev_injection_block:
            required_padding = (i - 1) % block_size
            break
        prev_injection_block = injection_block

    def enc_eliminate_prefix(payload):
        """Encrypt using `enc`, and cut off PREFIX.

        Now that we know how many characters we need to inject to force the
        secret we're trying to crack to start at the start of the buffer, we
        can create a new encryption function that does that and cuts off the
        encrypted prefix.

        Breaking this oracle will also break enc.
        """
        index = injection_block_index
        if required_padding:
            index = injection_block_index + 1
        return enc(('A' * required_padding) + payload)[index * block_size:]

    return break_oracle(enc_eliminate_prefix)

for i in xrange(30):
    print challenge14()

# vals = []
# for i in xrange(30):
#     vals.append(challenge14())
#     PREFIX = None
# print sorted(vals)
print 'done'
