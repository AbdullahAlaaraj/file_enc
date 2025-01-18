from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to generate and save an AES key
def generate_aes_key():
    # Generate a random 256-bit AES key
    aes_key = os.urandom(32)  # 32 bytes for AES-256

    # Save the AES key to a file
    with open("aes_key.bin", "wb") as aes_key_file:
        aes_key_file.write(aes_key)

    print("AES key generated and saved as aes_key.bin")
