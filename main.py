import os
from enc_dec import encrypt_file, decrypt_file
from keygen import generate_aes_key

def main():
    print("File Encryption Tool")
    print("1. Generate RSA Keys and AES Key")
    print("2. Encrypt a File")
    print("3. Decrypt a File")
    print("4. Exit")

    choice = input("Choose an option: ")

    if choice == "1":
        # Generate AES Key
        generate_aes_key()

    elif choice == "2":
        # Encrypt a file
        file_path = input("Enter the full file path to encrypt: ")

        # Check if the file exists
        if os.path.exists(os.path.expanduser(file_path)):
            encrypt_file(file_path)
        else:
            print(f"Error: The file at {file_path} does not exist.")
            main()

    elif choice == "3":
        # Decrypt a file
        file_path = input("Enter the full file path to decrypt: ")

        # Check if the file exists
        if os.path.exists(os.path.expanduser(file_path)):
            decrypt_file(file_path)
        else:
            print(f"Error: The file at {file_path} does not exist.")
            main()

    elif choice == "4":
        print("Exiting...")
        exit(0)

    else:
        print("Invalid choice. Please try again.")
        main()

if __name__ == "__main__":
    main()
