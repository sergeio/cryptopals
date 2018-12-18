from Crypto.Cipher import AES
import base64
import itertools
import random


class BadPadding(Exception):
    pass

def strip_pkcs7_padding(text, block_size):
    pad = text[-1]
    pad_i = ord(pad)
    if pad_i < 1 or len(text) < pad_i or len(text) < block_size:
        raise BadPadding
    # Last N characters must be chr(N)
    for c in itertools.islice(reversed(text), pad_i):
        if c != pad:
            raise BadPadding
    return text[:-pad_i]

def xor_bin(bin1, bin2):
    bytes1, bytes2 = map(bytearray, (bin1, bin2))
    xored = [bytes1[i] ^ bytes2[i % len(bytes2)] for i in xrange(len(bytes1))]
    return str(bytearray(xored))

def aes_ecb_decrypt(bytes, key):
    ciph = AES.new(key, AES.MODE_ECB)
    return ciph.decrypt(bytes)

def aes_ecb_encrypt(bytes, key):
    ciph = AES.new(key, AES.MODE_ECB)
    return ciph.encrypt(bytes)

def split_into_chunks(text, length):
    assert length > 0
    split = 0
    chunks = []
    while split < len(text):
        chunks.append(text[split:split + length])
        split += length
    return chunks

def pkcs7_padding(text, block_size):
    chars_needed = block_size - (len(text) % block_size)
    if not chars_needed:
        chars_needed = block_size
    return text + (chr(chars_needed) * chars_needed)

def make_random_aes_key(length=16):
    return ''.join(chr(random.randint(0, 128)) for _ in xrange(length))

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

KEY4 = ''
IV = ''
CHOSEN = ''
def cbc_padding_oracle():
    global KEY4, IV, CHOSEN
    if not KEY4:
        KEY4 = make_random_aes_key()
        IV = make_random_aes_key()
    cookies = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    ]
    if not CHOSEN:
        CHOSEN = pkcs7_padding(random.choice(cookies), len(KEY4))
    return aes_cbc_encrypt(CHOSEN, KEY4, IV), IV

def cbc_padding_oracle_decrypt(ciphertext, iv):
    block_size = 16
    plaintext = aes_cbc_decrypt(ciphertext, KEY4, iv)
    try:
        strip_pkcs7_padding(plaintext, block_size)
        return True
    except BadPadding:
        return False

def break_cbc_padding_oracle(ciphertext, iv):
    block_size = 16
    def break_nth_block(block_index):
        def break_n_th_last_character(block_index, n, broken_string):
            # broken_string should be the last n-1 already broken chars
            assert len(broken_string) == n - 1
            assert n <= block_size
            pad = chr(n) * n
            matches = []

            chunks = split_into_chunks(ciphertext, block_size)
            if block_index < 0:
                block_index = block_index + len(chunks)

            for guess_c in itertools.imap(chr, xrange(256)):
                maybe_edited_ciphertext = ciphertext
                maybe_edited_iv = iv

                last_n_guess = guess_c + broken_string
                xor_string = xor_bin(last_n_guess, pad)
                prepadded_xor_string = '\xff' * (block_size - n) + xor_string
                assert len(prepadded_xor_string) == block_size

                truncated_chunks = chunks[:block_index + 1]
                if block_index == 0:
                    maybe_edited_iv = xor_bin(prepadded_xor_string, iv)
                else:
                    edit_chunk = truncated_chunks[block_index - 1]
                    edit_chunk = xor_bin(prepadded_xor_string, edit_chunk)
                    truncated_chunks[block_index - 1] = str(edit_chunk)
                maybe_edited_ciphertext = ''.join(truncated_chunks)

                if cbc_padding_oracle_decrypt(maybe_edited_ciphertext,
                                              maybe_edited_iv):
                    matches.append(last_n_guess)
            assert len(matches) == 1
            return matches[0]

        broken = ''
        for i in xrange(1, block_size + 1):
            broken = break_n_th_last_character(block_index, i, broken)
        return broken

    return ''.join([break_nth_block(i)
                    for i in xrange(0, len(ciphertext) / block_size)])

def challenge17():
    intercepted_cookie, iv = cbc_padding_oracle()
    doctored = xor_bin(intercepted_cookie, '\x02'* 16)
    broken_cookie = break_cbc_padding_oracle(intercepted_cookie, iv)
    return base64.b64decode(broken_cookie)


print repr(challenge17())
