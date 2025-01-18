from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os


def generate_aes_key():
    aes_key = os.urandom(32)  # 256-bit AES key
    with open("aes_key.bin", "wb") as aes_key_file:
        aes_key_file.write(aes_key)

# Function to encrypt the file contents using AES
def encrypt_file(file_path):
    # Expand the user directory (`~`) to the full path
    file_path = os.path.expanduser(file_path)
    
    # Check if the AES key exists
    if not os.path.exists("aes_key.bin"):
        print("AES key not found. Generating a new AES key.")
        generate_aes_key()  # Generate and save AES key if it doesn't exist

    # Load the AES key
    with open("aes_key.bin", "rb") as aes_key_file:
        aes_key = aes_key_file.read()

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"Error: The file at {file_path} does not exist.")
        return

    # Open the file and read the data
    with open(file_path, "rb") as file:
        data = file.read()

    # Pad the data to be a multiple of the AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()  # 128-bit block size for AES
    padded_data = padder.update(data) + padder.finalize()

    # Generate a random IV
    iv = os.urandom(16)

    # Encrypt the padded file data using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save the IV and encrypted data to a new file
    encrypted_file_path = f"encrypted_{os.path.basename(file_path)}.enc"
    with open(encrypted_file_path, "wb") as enc_file:
        enc_file.write(iv)  # Prepend the IV to the ciphertext
        enc_file.write(ciphertext)

    print(f"File encrypted successfully! Encrypted file saved as: {encrypted_file_path}")

# Function to decrypt the file contents using AES
def decrypt_file(file_path):
    # Expand the user directory (`~`) to the full path
    file_path = os.path.expanduser(file_path)
    
    # Check if the AES key exists
    if not os.path.exists("aes_key.bin"):
        print("AES key not found. Please generate the key first.")
        return

    # Load the AES key
    with open("aes_key.bin", "rb") as aes_key_file:
        aes_key = aes_key_file.read()

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"Error: The file at {file_path} does not exist.")
        return

    # Open the encrypted file and read the data
    with open(file_path, "rb") as enc_file:
        iv = enc_file.read(16)  # Read the IV (first 16 bytes)
        encrypted_data = enc_file.read()  # The rest is the ciphertext

    # Decrypt the data using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the decrypted data to a new file
    decrypted_file_path = f"decrypted_{os.path.basename(file_path)}"
    with open(decrypted_file_path, "wb") as dec_file:
        dec_file.write(original_data)

    print(f"File decrypted successfully! Decrypted file saved as: {decrypted_file_path}")
