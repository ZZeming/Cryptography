import random
import math
p = 631301025971923864392280319321
q = 161494410882474662249657376601

# Extended Euclidean Algorithm
def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

# Modular inverse using Extended Euclidean Algorithm
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
    p = generate_prime(bit_length)
    q = generate_prime(bit_length)
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

# Convert ASCII string to integer
def ascii_to_integer(string):
    return int(string.encode('utf-8').hex(), 16)

# Convert integer to ASCII string
def integer_to_ascii(number):
    hex_string = hex(number)[2:]
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    byte_string = bytes.fromhex(hex_string)
    return byte_string.decode('utf-8')

# Test RSA encryption and decryption
def test_rsa():
    bit_length = 2048
    message = "HELP!"

    public_key, private_key = generate_rsa_key_pair(bit_length)

    # Encryption
    plaintext = ascii_to_integer(message)
    ciphertext = rsa_encrypt(plaintext, public_key)

    # Decryption
    decrypted_text = rsa_decrypt(ciphertext, private_key)
    decrypted_message = integer_to_ascii(decrypted_text)

    print("Original message:", message)
    print("Decrypted message:", decrypted_message)

test_rsa()
