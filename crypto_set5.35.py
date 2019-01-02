import random
import sha1

from crypto_set3 import aes_cbc_decrypt
from crypto_set3 import aes_cbc_encrypt
from crypto_set3 import pkcs7_padding
from crypto_set3 import strip_pkcs7_padding

# A->B
#     Send "p", "g", "A"
# B->A
#     Send "B"
# A->B
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
# B->A
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv 

def initiate_diffie_hellman(message):
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    a = random.randint(0, 37)
    A = (g ** a) % p
    B = yield p, g, A
    print 'B', B
    session = (B ** a) % p
    key = sha1.sha1_str(str(session))[:16]
    iv = random.randint(0, 16 * 8)
    yield aes_cbc_encrypt(pkcs7_padding(message, 16), key, iv), iv

def mitm(p, g, A):
    bob = respond_diffie_hellman(p, g, p)
    _B = bob.send(None)
    ciphertext, iv = yield p
    plaintext, iv = bob.send((ciphertext, iv))
    key = sha1.sha1_str('0')[:16]
    padded = aes_cbc_decrypt(ciphertext, key, iv)
    print 'MITM thinks A sent %r' % strip_pkcs7_padding(padded, 16)
    yield plaintext, iv

def respond_diffie_hellman(p, g, A):
    b = random.randint(0, 37)
    B = (g ** b) % p
    session = (A ** b) % p
    ciphertext, iv = yield B
    session = (A ** b) % p
    key = sha1.sha1_str(str(session))[:16]
    padded = aes_cbc_decrypt(ciphertext, key, iv)
    print 'B thinks A sent %r' % strip_pkcs7_padding(padded, 16)
    yield ciphertext, iv

def echo(message, sender, receiver):
    alice = sender(message)
    p, g, A = alice.send(None)
    bob = receiver(p, g, A)
    B = bob.send(None)
    cipher, iv = alice.send(B)
    echoed, iv = bob.send((cipher, iv))
    return

def challenge34():
    message = 'Hello, friend!'
    echo(message, initiate_diffie_hellman, respond_diffie_hellman)
    # echo(message, initiate_diffie_hellman, mitm)


print repr(challenge34())
