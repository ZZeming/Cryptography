import random
import hashlib
import math
from Crypto.Cipher import AES

# Hard coded prime numbers to avoid wait time
p = 631301025971923864392280319321
q = 161494410882474662249657376601

# Euclidean Algorithm
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

# Do Modular inverse
def mod_inverse(a, m):
    gcd, x, _ = extended_gcd(a, m)
    if gcd == 1:
        return x % m
    raise ValueError("Inverse does not exist.")

# Generate random prime of specified bit length
def generate_prime(bit_length):
    while True:
        p = random.randint(2 ** (bit_length - 1), 2 ** bit_length - 1)
        if is_prime(p):
            return p

# Check if a number is prime
def is_prime(num):
    if num < 2:
        return False
    for i in range(2, math.isqrt(num) + 1):
        if num % i == 0:
            return False
    return True

# Generate RSA key pair
def generate_rsa_key_pair(bit_length):
    #p = generate_prime(bit_length)
    #q = generate_prime(bit_length)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# Encrypt message using RSA public key
def rsa_encrypt(message, public_key):
    e, n = public_key
    if message >= n:
        raise ValueError("Message is too large to encrypt.")
    return pow(message, e, n)

# Decrypt message using RSA private key
def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

# Perform MITM attack to modify ciphertext
def mitm_attack(ciphertext, public_key_mallory):
    e_mallory, n_mallory = public_key_mallory

    # Choose a random factor to modify the ciphertext
    factor = random.randint(2, n_mallory - 1)

    # Modify ciphertext using the factor
    ciphertext_modified = (ciphertext * pow(factor, e_mallory, n_mallory)) % n_mallory

    return ciphertext_modified, factor

# Decrypt modified ciphertext and recover symmetric key
def decrypt_ciphertext(ciphertext_modified, factor, private_key_bob):
    d_bob, n_bob = private_key_bob

    # Decrypt modified ciphertext
    decrypted_modified_ciphertext = pow(ciphertext_modified, d_bob, n_bob)

    # Recover symmetric key by dividing by the factor
    symmetric_key = (decrypted_modified_ciphertext * mod_inverse(factor, n_bob)) % n_bob

    return symmetric_key

# Encrypt plaintext using AES-CBC with symmetric key
def aes_cbc_encrypt(plaintext, key):
    iv = bytes([random.randint(0, 255) for _ in range(16)])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))
    return iv + ciphertext

# Decrypt ciphertext using AES-CBC with symmetric key
def aes_cbc_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext

# Pad plaintext to multiple of 16 bytes for AES-CBC
def pad(plaintext):
    padding_length = 16 - (len(plaintext) % 16)
    padding = bytes([padding_length]) * padding_length
    return plaintext + padding

# Unpad plaintext by removing PKCS7 padding
def unpad(plaintext):
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]

# Test the MITM attack on the protocol
def test_mitm_attack():
    bit_length = 2048
    message = "Hi Bob!"

    # Generate Alice's public key and Bob's key pair
    public_key_alice, _ = generate_rsa_key_pair(bit_length)
    _, private_key_bob = generate_rsa_key_pair(bit_length)

    # Encrypt the message using Alice's public key
    plaintext = message.encode('utf-8')
    plaintext_int = int.from_bytes(plaintext, 'big')
    ciphertext = rsa_encrypt(plaintext_int, public_key_alice)

    # Use MITM attack to modify ciphertext
    ciphertext_modified, factor = mitm_attack(ciphertext, public_key_alice)

    # Decrypt modified ciphertext and recover symmetric key
    symmetric_key = decrypt_ciphertext(ciphertext_modified, factor, private_key_bob)

    # Generate symmetric key using SHA256
    key = hashlib.sha256(symmetric_key.to_bytes((symmetric_key.bit_length() + 7) // 8, 'big')).digest()

    # Encrypt plaintext using AES-CBC with the symmetric key
    ciphertext_aes = aes_cbc_encrypt(plaintext, key)

    print("Original message:", message)
    print("Recovered message:", aes_cbc_decrypt(ciphertext_aes, key).decode('utf-8'))

test_mitm_attack()