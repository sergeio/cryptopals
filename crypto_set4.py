import datetime
import string
import urllib

from crypto_set1and2 import make_random_aes_key
from crypto_set3 import BadPadding
from crypto_set3 import aes_cbc_decrypt
from crypto_set3 import aes_cbc_encrypt
from crypto_set3 import make_keystream
from crypto_set3 import pkcs7_padding
from crypto_set3 import split_into_chunks
from crypto_set3 import strip_pkcs7_padding
from crypto_set3 import xor_str
import sha1

import requests


def aes_ctr_encrypt(plaintext, key):
    block_size = len(key)
    i = 0
    chunks = split_into_chunks(plaintext, block_size)
    encrypted_chunks = [
        xor_str(chunk, make_keystream(i, key)[:len(chunk)])
        for i, chunk in enumerate(chunks)
    ]
    return ''.join(encrypted_chunks)

def aes_ctr_edit(ciphertext, key, offset, newtext):
    plaintext = aes_ctr_encrypt(ciphertext, key)
    head, tail = plaintext[:offset], plaintext[offset:]
    return aes_ctr_encrypt(head + newtext + tail, key)

def challenge25():
    plaintext = 'My extremely personal secret'
    key = make_random_aes_key()
    ciphertext = aes_ctr_encrypt(plaintext, key)

    inject = 'A' * len(ciphertext)
    edited_ciphertext = aes_ctr_edit(ciphertext, key, 0, inject)
    recovered_keystream = xor_str(inject, edited_ciphertext)
    return xor_str(ciphertext, recovered_keystream)

KEY = ''
def encrypt_url(user_data):
    global KEY
    if not KEY:
        KEY = make_random_aes_key()
    user_data = user_data.replace(';', '%%Q')
    user_data = user_data.replace('=', '%%E')
    prepend = "comment1=cooking%20MCs;userdata="
    append = ";comment2=%20like%20a%20pound%20of%20bacon"
    to_encrypt = prepend + user_data + append
    return aes_ctr_encrypt(to_encrypt, KEY)

def is_admin_url(encrypted):
    decrypted = aes_ctr_encrypt(encrypted, KEY)
    return ';admin=true;' in decrypted

def edit_ctr_ciphertext_make_admin(ciphertext, prepend, admin_string):
    block_size = 16
    edit_block_index = len(prepend) / block_size
    payload_text = 'A' * (block_size - len(admin_string)) + admin_string
    payload = xor_str('A' * block_size, payload_text)
    chunks = split_into_chunks(ciphertext, block_size)
    chunks[edit_block_index] = str(xor_str(chunks[edit_block_index], payload))
    return ''.join(chunks)

def challenge26():
    admin_string = ';admin=true;'
    prepend = "comment1=cooking%20MCs;userdata="
    encrypted = encrypt_url('A'* 16)
    assert not is_admin_url(encrypted)
    edited = edit_ctr_ciphertext_make_admin(encrypted, prepend,admin_string)
    assert is_admin_url(edited)
    return is_admin_url(edited)

KEY2 = ''
def c27_sender(text):
    global KEY2
    if not KEY2:
        KEY2 = make_random_aes_key()
    to_encrypt = pkcs7_padding(text, len(KEY2))

    return aes_cbc_encrypt(to_encrypt, KEY2, KEY2)

class BadDecrypt(Exception):
    pass

def c27_receiver(ciphertext):
    decrypted = aes_cbc_decrypt(ciphertext, KEY2, KEY2)
    try:
        decrypted = strip_pkcs7_padding(decrypted, len(KEY2))
    except BadPadding:
        pass

    for c in decrypted:
        if c not in string.printable:
            raise BadDecrypt(decrypted)

    return decrypted

def c27_attacker(ciphertext):
    block_size = 16
    chunks = split_into_chunks(ciphertext, block_size)
    edited_ciphertext = ''.join([chunks[0], '\x00' * block_size, chunks[0]])
    decrypted = ''
    try:
        c27_receiver(edited_ciphertext)
    except BadDecrypt as e:
        decrypted = e.message

    chunks = split_into_chunks(decrypted, block_size)
    key = xor_str(chunks[0], chunks[2])
    assert key == KEY2
    plaintext = aes_cbc_decrypt(ciphertext, key, key)
    return plaintext

def challenge27():
    plaintext = 'I am confiding in you with my important secret, friend'
    ciphertext = c27_sender(plaintext)
    cracked_plaintext = c27_attacker(ciphertext)
    assert plaintext == c27_receiver(ciphertext)
    assert cracked_plaintext.startswith(plaintext)
    return cracked_plaintext

def sign_message(message, key):
    return sha1.sha1(key + message)

def forge_signature_make_admin(signature, message):
    admin_string = ';admin=true;'

    sha_state = split_sha_into_registers(signature)
    padded_length = len(sha1.ml_pad_message(message))

    pairs = []
    for key_length in xrange(4, 512):
        original_padded_message = sha1.ml_pad_message(
            message,
            length=(len(message) + key_length),
            faking_message=True
        )

        forged_message = original_padded_message + admin_string

        forged_signature = sha1.sha1(
            admin_string,
            state=sha_state,
            length=len(forged_message) + key_length)

        pairs.append((forged_message, forged_signature))

    return pairs

def admin_validator(message):
    return ';admin=true;' in message

def split_sha_into_registers(sha):
    registers = [int((sha & (0xffffffff << (32 * i))) >> (32 * i))
                 for i in xrange(4, -1, -1)]
    return registers

def challenge29():
    key = 'yellow submarine'
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    signature = sign_message(message, key)

    assert not admin_validator(message)
    assert sign_message(message, key) == signature

    pairs = forge_signature_make_admin(signature, message)

    for mess, sign in pairs:
        try:
            if sign_message(mess, key) == sign:
                forged_message = mess
                forged_signature = sign
        except:
            pass

    assert admin_validator(forged_message)
    assert sign_message(forged_message, key) == forged_signature
    return forged_message

def challenge30():
    # Skipping.  Doesn't look fun.  Same as 29, and will probably still take a
    # fair amount of debug time, despite the description asserting most of the
    # time will be spent looking for an md4 implementation.
    pass

def break_file_hash(filename):
    def guess(signature):
        now = datetime.datetime.now()
        url = 'http://localhost:5000/?file=%s&signature=%s' % (
            filename, signature)
        request = requests.get(url)
        msecs = (datetime.datetime.now() - now).total_seconds() * 1000
        return request, msecs

    def break_character(preceeding):
        NUM_TRIES = 100
        timing = []
        for c in map(str, xrange(10)):
            # This is very very slow : (
            guess_sha = preceeding + c + 'X'
            response, msecs = guess(guess_sha)
            total_msecs = sum(
                guess(guess_sha)[1] for _ in xrange(NUM_TRIES - 1)) + msecs
            if response.status_code == 200:
                return c, True
            timing.append((total_msecs, c))
        timing = sorted(timing, reverse=True)
        leader_margin = timing[0][0] - timing[1][0]
        if leader_margin > 200:
            return timing[0][1], False
        else:
            return break_character(preceeding)

    broken_sha = ''
    done = False
    while not done:
        c, done = break_character(broken_sha)
        broken_sha += c
    return int(broken_sha)


sha=''
def challenge3132():
    from fileserver import get_file_sha
    filename = '4.txt'
    global sha
    sha = get_file_sha(filename)
    broken_hash = break_file_hash(filename)
    assert broken_hash == sha
    return broken_hash == sha

def challenge33():
    pass


print repr(challenge33())
