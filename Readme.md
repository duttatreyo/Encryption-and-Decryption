# Python Encryption & Decryption Utility

This utility is a Python-based command-line tool developed to provide encryption, decryption, and hashing functionalities. It supports various ciphers and hashing algorithms, providing a user-friendly interface to perform cryptographic operations.


## Features
Supports Encryption & Decryption using Caesar and Atbash ciphers.
Supports Hashing using SHA-256, MD5, and other hashing algorithms.
Supports Salt addition during hashing.
User-friendly command-line interface.


## How to Use
Run the Python script in a terminal or command prompt.
Follow the prompts to select whether you want to encrypt, decrypt, or hash your input.
Based on the chosen operation, select the desired cipher or hashing algorithm.
Input the plaintext or ciphertext as prompted.
If hashing, you have the option to add salt to your input.
The program will output the result of the operation.

Alternatively, you have the option to download the HTML code and employ the utility for encryption or decryption tasks.


## Requirements
Python 3.x
Required Libraries: hashlib , cryptography

## To install Libraries: 
pip install hashlib
pip install cryptography

## Example
```$python encrypt_or_decrypt.py```


## Limitations
SHA-256 and other hashing algorithms are one-way functions; hence only hashing is supported.
The utility does not validate whether the input for decryption is valid ciphertext for the chosen cipher.



---

Please be aware that some functionalities, like AES encryption/decryption and salting, are not included in HTML code due to the intricate nature of their implementation in JavaScript and the absence of corresponding methods in the Web Crypto API.

---
