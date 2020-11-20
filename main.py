import random
import functools
import operator

# Euclid's algorithm for determining the greatest common divisor
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


# Euclid's extended algorithm for determining the greatest common divisor
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num ** 0.5) + 2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)

    # Find comprime int for phi and e
    e = random.randrange(1, phi)
    g = egcd(e, phi)

    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)


    d = modinv(e, phi)

    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def hash(n, plaintext):
    m = [(ord(char) - 1040) for char in plaintext]
    return functools.reduce(operator.add, m)

# encrypted sign
def encrypt_hash(pk, hash):
    key, n = pk
    return (hash ** key) % n

def decrypt_hash(pk, hash):
    key, n = pk
    return ((hash ** key) % n)

def encrypt(pk, plaintext):
    # Cyrilic ASCI has 1040 base for uppercases
    key, n = pk
    cipher = [((ord(char) - 1040) ** key) % n for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    key, n = pk
    plain = [chr(((char ** key) % n) + 1040) for char in ciphertext]
    return ''.join(plain)


if __name__ == '__main__':
 

    public, private = generate_keypair(p, q)
    _, n = public

    sender_message = "ПРИКАЗЫВАЮ"

    # Sender

    print("Sender hash:")
    sender_hash = hash(n, sender_message)
    print(sender_hash)

    print("Sender encrypted sign")
    sender_encrypted_sign =  encrypt_hash(public, sender_hash)
    print(sender_encrypted_sign)

    print("Sender Encrypted message")
    sender_encrypted_msg = encrypt(public, sender_message)
    print(sender_encrypted_msg)

    # Receiver

    print("----------")

    print("Receiver decrypted message:")
    receiver_decrypted_message = decrypt(private, sender_encrypted_msg)
    print(receiver_decrypted_message)

    print("Receiver hash:")
    receiver_hash = hash(n, receiver_decrypted_message)
    print(receiver_hash)

    print("Receiver decrypted sign:")
    receiver_decrypted_sign = decrypt_hash(private, sender_encrypted_sign)
    print(receiver_decrypted_sign)

    print("Validate content")
    print(receiver_hash == receiver_decrypted_sign)

