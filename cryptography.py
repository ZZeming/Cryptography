import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import random

p = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)
g = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)
key_size = 16  # 16 bytes for AES-128

def diffie_hellman(p, g):
    # Alice's side
    a = random.randint(1, p - 1)
    A = pow(g, a, p)

    # tampered_A = p


    # Bob's side
    b = random.randint(1, p - 1)
    B = pow(g, b, p)

    # tampered_B = p
    print(A)
    print(B)

    # Shared
    s = pow(B, a, p)
    K = hashlib.sha256(hex(s).encode()).digest()[:key_size]

    return A, B, K

def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher.iv + cipher_text

def decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return plain_text

def main():
        
    mallory_g = random.choice([1, p, p - 1])

    A, B, K = diffie_hellman(p, mallory_g)

    alice_message = "Hi Bob!".encode()
    encrypted_alice_message = encrypt(alice_message, K)

    decrypted_alice_message = decrypt(encrypted_alice_message, K)
    print("Decrypted message from Alice to Bob:", decrypted_alice_message.decode())

    bob_message = "Hi Alice!".encode()
    encrypted_bob_message = encrypt(bob_message, K)

    decrypted_bob_message = decrypt(encrypted_bob_message, K)
    print("Decrypted message from Bob to Alice:", decrypted_bob_message.decode())

if __name__ == "__main__":
    main()