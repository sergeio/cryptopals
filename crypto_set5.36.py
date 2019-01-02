import random
import hashlib

# C->S
#     Send I, A=g**a % N (a la Diffie Hellman)
# S->C
#     Send salt, B=kv + g**b % N
# S, C
#     Compute string uH = SHA256(A|B), u = integer of uH
# C
#
#         Generate string xH=SHA256(salt|password)
#         Convert xH to integer x somehow (put 0x on hexdigest)
#         Generate S = (B - k * g**x)**(a + u * x) % N
#         Generate K = SHA256(S)
#
# S
#
#         Generate S = (A * v**u) ** b % N
#         Generate K = SHA256(S)
#
# C->S
#     Send HMAC-SHA256(K, salt)
# S->C
#     Send "OK" if HMAC-SHA256(K, salt) validates

def client():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3
    I = 'example@example.com'
    password = 'yellow submarine'

    a = random.randint(0, 37)
    A = pow(g, a, p)
    salt, B = yield I, A
    u = int(hashlib.sha256(str(A) + str(B)).hexdigest(), base=16)

    #         Generate string xH=SHA256(salt|password)
    #         Convert xH to integer x somehow (put 0x on hexdigest)
    #         Generate S = (B - k * g**x)**(a + u * x) % N
    #         Generate K = SHA256(S)
    x = int(hashlib.sha256(str(salt) + password).hexdigest()[:5], base=16)
    S = pow(B - k * pow(g, x), a + u * x, p)
    K = int(hashlib.sha256(str(S)).hexdigest(), base=16)
    yield hashlib.sha256(str(salt) + str(K)).hexdigest()

def server():
    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3
    I = 'example@example.com'
    password = 'yellow submarine'

    salt = random.randint(0, 2 ** 16)
    _x = int(hashlib.sha256(str(salt) + password).hexdigest()[:5], base=16)
    v = pow(g, _x, p)
    #     Send salt, B=kv + g**b % N
    b = random.randint(0, 37)
    B = k * v + pow(g, b, p)
    # yield None
    I_client, A = yield salt, B
    assert I_client == I
    u = int(hashlib.sha256(str(A) + str(B)).hexdigest(), base=16)

    #         Generate S = (A * v**u) ** b % N
    #         Generate K = SHA256(S)
    print pow(v, u)
    S = pow(A * pow(v, u), b, p)
    K = int(hashlib.sha256(S).hexdigest(), base=16)
    #     Send HMAC-SHA256(K, salt)
    # yield hashlib.sha256(str(salt) + str(K))

def talk(initiator, responder):
    c = initiator()
    s = responder()

    c_out = c.send(None)
    #i a
    s_out = s.send(None)
    # salt b
    try:
        while True:
            print 's', s_out
            print 'c', c_out
            c_out_new = c.send(s_out)
            s_out_new = s.send(c_out)
            c_out, s_out = c_out_new, s_out_new
    except StopIteration:
        pass

    # return c_out, s_out


def challenge36():
    return talk(client, server)

print repr(challenge36())
