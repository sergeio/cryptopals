from crypto_set1and2 import make_random_aes_key
from crypto_set3 import split_into_chunks
from crypto_set3 import xor_str
from crypto_set3 import make_keystream


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

print repr(challenge26())