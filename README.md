# Multiprocessing S-DES Decryption & BruteForce Attack Testing

Consider the following ciphertext outputted from applying the Simplified Data Encryption Standard (S-DES) algorithm using the key 3DA: 69

Where all the above representations are in Hexadecimal.

You are required to write a computer program that decrypts the above ciphertext and gets the original plaintext. Thereafter, you are required to simulate a brute-force attack that assumes knowing the plaintext-ciphertext pair in order to get the symmetric key.

*The following are the required tasks:*

1. Write an S-DES decryption function that takes a ciphertext alongside with the key as input and returns the original plaintext.

2. Write a program that calls the implemented S-DES decryption function using the key 3DA and ciphertext block 69. All in Hexadecimal numbering system. Your program should print the original plaintext.

3. Given the obtained plaintext and ciphertext, write a computer program that makes a brute-force attack to get the symmetric key. Run your program and check how much time it takes until it gets the key.

4. Use multi-threading approach to speed-up the brute-force attack program you implement in (3).
