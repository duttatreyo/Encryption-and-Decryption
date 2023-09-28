import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def caesar_encrypt(plain_text, shift):
    cipher_text = ""
    for char in plain_text:
        if char.isalpha():
            shift_amount = shift % 26
            unicode_offset = 65 if char.isupper() else 97
            cipher_text += chr((ord(char) - unicode_offset + shift_amount) % 26 + unicode_offset)
        else:
            cipher_text += char
    return cipher_text


def caesar_decrypt(cipher_text, shift):
    return caesar_encrypt(cipher_text, -shift)


def atbash_encrypt_decrypt(text):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            unicode_offset = 90 if char.isupper() else 122
            encrypted_text += chr(unicode_offset - ord(char) + (65 if char.isupper() else 97))
        else:
            encrypted_text += char
    return encrypted_text


def md5_hash(text, salt=""):
    return hashlib.md5((salt + text).encode()).hexdigest()


def sha256_hash(text, salt=""):
    return hashlib.sha256((salt + text).encode()).hexdigest()


def aes_encrypt(text, key):
    key = key.ljust(32)[:32].encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return (iv + encryptor.update(text.encode()) + encryptor.finalize()).hex()


def aes_decrypt(cipher_text, key):
    key = key.ljust(32)[:32].encode()
    cipher_bytes = bytes.fromhex(cipher_text)
    iv = cipher_bytes[:16]
    cipher_text = cipher_bytes[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(cipher_text) + decryptor.finalize()).decode()


def main():
    while True:
        text = input("Enter the plain/cipher text: ")
        choice = input("Do you want to (e)ncrypt, (d)ecrypt, or (h)ash the text?: ").lower()

        print("1. Caesar Cipher")
        print("2. Atbash Cipher")
        print("3. MD5 Hash")
        print("4. SHA-256 Hash")
        print("5. AES Encryption")
        cipher_choice = input("Choose the cipher/hash (1-5): ")

        salt = ""
        if cipher_choice in ['3', '4'] and choice == 'h':
            add_salt = input("Do you want to add salt to the hash? (y/n): ").lower()
            salt = input("Enter the salt value: ") if add_salt == 'y' else ""

        if cipher_choice == '1':
            shift = int(input("Enter the shift value for Caesar Cipher: "))
            if choice == 'e':
                print("Encrypted Text: ", caesar_encrypt(text, shift))
            elif choice == 'd':
                print("Decrypted Text: ", caesar_decrypt(text, shift))
            else:
                print("Invalid Choice! Please enter 'e' for encrypt or 'd' for decrypt.")
        elif cipher_choice == '2':
            print("Encrypted/Decrypted Text: ", atbash_encrypt_decrypt(text))
        elif cipher_choice == '3':
            if choice == 'h':
                print("MD5 Hash: ", md5_hash(text, salt))
            else:
                print("Invalid Choice! MD5 can only hash the text, please enter 'h' for hash.")
        elif cipher_choice == '4':
            if choice == 'h':
                print("SHA-256 Hash: ", sha256_hash(text, salt))
            else:
                print("Invalid Choice! SHA-256 can only hash the text, please enter 'h' for hash.")
        elif cipher_choice == '5':
            key = input("Enter a key for AES Encryption/Decryption: ")
            if choice == 'e':
                print("Encrypted Text: ", aes_encrypt(text, key))
            elif choice == 'd':
                print("Decrypted Text: ", aes_decrypt(text, key))
            else:
                print("Invalid Choice! Please enter 'e' for encrypt or 'd' for decrypt.")
        else:
            print("Invalid Cipher/Hash Choice! Please choose between 1-5.")

        another = input("Do you want to encrypt/decrypt/hash another text? (y/n): ").lower()
        if another != 'y':
            break


if __name__ == "__main__":
    main()
