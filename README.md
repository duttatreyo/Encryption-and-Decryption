Cryptographic Utility

This is a simple, user-friendly cryptographic utility tool created to demonstrate encryption, decryption, and hashing using different ciphers and hashing algorithms. It is implemented using HTML, CSS, and JavaScript, allowing users to interact with it through a web browser.

Features
Encryption and Decryption: Supports Caesar and Atbash ciphers.
Hashing: Supports SHA-256 hashing algorithm.
User-Friendly Interface: Easily select between operations and algorithms, input text, and view results.
Safe & Secure: Performs all operations client-side, meaning your data never leaves your computer.

How to Use
Open the index.html file in a modern web browser.
Enter the text you want to encrypt, decrypt, or hash in the provided textarea.
Select the operation (Encrypt, Decrypt, or Hash) you want to perform.
Choose the cipher or hashing algorithm you want to use.
If encrypting or decrypting using the Caesar cipher, specify the shift value.
If hashing using SHA-256, optionally add a salt.
Click the "Perform Operation" button to execute the selected operation and view the result.

Supported Ciphers & Hashing Algorithms
Ciphers
Caesar Cipher: A substitution cipher where each letter in the plaintext is shifted a certain number of places down or up the alphabet.
Atbash Cipher: A substitution cipher where the alphabet is reversed.
Hashing Algorithms
SHA-256: A cryptographic hash function from the SHA-2 family, producing a 256-bit (32-byte) hash value, typically rendered as a 64-digit hexadecimal number.

Note
For SHA-256, only hashing is supported as it is a one-way function and cannot be decrypted.
All operations are performed on the client side; no data is sent to or stored on a server.
