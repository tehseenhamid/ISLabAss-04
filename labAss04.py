#############################################
#   ASSIGNMENT: RSA, PyCryptodome, Signatures
#   All Tasks Implemented in One File
#   Author: Tehseen Hamid
#############################################

############################################################
#                   TASK 1: SIMPLE RSA (NO LIBRARIES)
#   - Manual RSA implementation using small primes
#   - Demonstrates the full process: key generation,
#     encryption, and decryption
############################################################

# Step 1: Choose small prime numbers (for demo only)
p = 11
q = 13

# Step 2: Compute modulus n = p * q
n = p * q

# Step 3: Compute Euler's Totient
phi = (p - 1) * (q - 1)

# Step 4: Select e such that gcd(e, phi) = 1
# e = 7 chosen because it works and is small
e = 7

# Step 5: Manual Modular Inverse using brute force search
def mod_inverse(e, phi):
    """
    Finds modular inverse of e mod phi using simple brute force.
    Returns d such that (d * e) % phi == 1.
    """
    for d in range(1, phi):
        if (d * e) % phi == 1:
            return d
    return None

# Compute private key exponent
d = mod_inverse(e, phi)

# Display keys
print("----- TASK 1: SIMPLE RSA -----")
print("Public Key (e, n):", (e, n))
print("Private Key (d, n):", (d, n))


# RSA Encrypt/Decrypt single characters
def encrypt_char(char, e, n):
    return pow(ord(char), e, n)

def decrypt_char(cipher, d, n):
    return chr(pow(cipher, d, n))

# Apply RSA to entire string
def encrypt_message(message, e, n):
    return [encrypt_char(ch, e, n) for ch in message]

def decrypt_message(cipher_list, d, n):
    return "".join(decrypt_char(c, d, n) for c in cipher_list)

# Testing RSA with short message
message = "Saim"
cipher = encrypt_message(message, e, n)
plain = decrypt_message(cipher, d, n)

print("\nOriginal Message:", message)
print("Encrypted (numbers):", cipher)
print("Decrypted:", plain)


############################################################
#             TASK 2: RSA WITH PYCRYPTODOME
#   - Modern RSA using real 2048-bit keys
#   - Demonstrates secure encryption/decryption
############################################################

print("\n\n----- TASK 2: RSA WITH PYCRYPTODOME -----")

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate strong RSA keys (2048 bits)
key = RSA.generate(2048)
public_key = key.publickey()

print("\n2048-bit keys generated successfully!")
print("Public Key (preview):", public_key.export_key().decode()[:100], "...")

# Sample message for RSA encryption
msg = b"Hello RSA World!"

# Encrypt using OAEP padding (secure)
cipher_rsa = PKCS1_OAEP.new(public_key)
encrypted_msg = cipher_rsa.encrypt(msg)

# Decrypt using private key
decipher_rsa = PKCS1_OAEP.new(key)
decrypted_msg = decipher_rsa.decrypt(encrypted_msg)

print("\nEncrypted (hex):", encrypted_msg.hex())
print("Decrypted:", decrypted_msg.decode())


############################################################
#           TASK 3: DIGITAL SIGNATURE CREATION
#   - Signing data using RSA private key
#   - Verifying signature using public key
#   - Demonstrates message integrity + authentication
############################################################

print("\n\n----- TASK 3: DIGITAL SIGNATURES -----")

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Message to be signed
message_to_sign = b"This is my message."

# Generate SHA-256 hash of the message
hash_object = SHA256.new(message_to_sign)

# Sign the hash with the private key
signature = pkcs1_15.new(key).sign(hash_object)

print("\nSignature (hex):", signature.hex())

# Verify the signature
try:
    pkcs1_15.new(public_key).verify(hash_object, signature)
    print("Signature Verified Successfully!")
except:
    print("Signature Verification Failed!")

# Modify the message to cause verification failure
fake_message = b"This is my message!"
fake_hash = SHA256.new(fake_message)

# Verification should now fail
try:
    pkcs1_15.new(public_key).verify(fake_hash, signature)
    print("Verification passed (unexpected!)")
except:
    print("Verification Failed (Message was changed as expected)")


############################################################
#                      END OF FILE
############################################################
