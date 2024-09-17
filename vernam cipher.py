import random
import string

def generate_key(length):
    """Generate a random key of given length."""
    return ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation + ' ') for _ in range(length))

def xor_strings(s1, s2):
    """XOR two strings of the same length."""
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

def vernam_encrypt(plaintext, key):
    """Encrypt the plaintext using the Vernam cipher."""
    if len(plaintext) != len(key):
        raise ValueError("The length of the key must be equal to the length of the plaintext.")
    return xor_strings(plaintext, key)

def vernam_decrypt(ciphertext, key):
    """Decrypt the ciphertext using the Vernam cipher."""
    if len(ciphertext) != len(key):
        raise ValueError("The length of the key must be equal to the length of the ciphertext.")
    return xor_strings(ciphertext, key)

def main():
    # Input plaintext
    plaintext = input("Enter the plaintext: ")
    
    # Generate key of the same length as the plaintext
    key = generate_key(len(plaintext))
    
    # Encrypt the plaintext
    ciphertext = vernam_encrypt(plaintext, key)
    print(f"Ciphertext: {ciphertext}")
    
    # Decrypt the ciphertext
    decrypted_text = vernam_decrypt(ciphertext, key)
    print(f"Decrypted text: {decrypted_text}")
    
    # Output the key (for demonstration purposes; in a real application, the key should be kept secret)
    print(f"Key: {key}")

if __name__ == "__main__":
    main()
