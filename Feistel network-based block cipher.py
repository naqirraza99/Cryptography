def feistel_round(left, right, key):
    """Perform one round of the Feistel function."""
    # Example round function: XOR with the key
    return right, left ^ (right + key)

def feistel_encrypt(plaintext, key):
    """Encrypt plaintext using a Feistel network with a single round."""
    # Convert plaintext to two 8-bit halves
    left = int.from_bytes(plaintext[:len(plaintext) // 2], 'little')
    right = int.from_bytes(plaintext[len(plaintext) // 2:], 'little')

    # Perform Feistel round
    left, right = feistel_round(left, right, key)

    # Combine halves and return ciphertext
    return left.to_bytes(len(plaintext) // 2, 'little') + right.to_bytes(len(plaintext) // 2, 'little')

def feistel_decrypt(ciphertext, key):
    """Decrypt ciphertext using a Feistel network with a single round."""
    # Convert ciphertext to two 8-bit halves
    left = int.from_bytes(ciphertext[:len(ciphertext) // 2], 'little')
    right = int.from_bytes(ciphertext[len(ciphertext) // 2:], 'little')

    # Perform Feistel round (inverse operation)
    right, left = feistel_round(left, right, key)

    # Combine halves and return plaintext
    return left.to_bytes(len(ciphertext) // 2, 'little') + right.to_bytes(len(ciphertext) // 2, 'little')

def main():
    # Key for Feistel rounds (must be a small integer for simplicity)
    key = 0x1F

    # Input plaintext (must be an even number of bytes for simplicity)
    plaintext = input("Enter the plaintext (even number of bytes): ").encode()

    if len(plaintext) % 2 != 0:
        print("Plaintext length must be an even number of bytes.")
        return

    # Encrypt the plaintext
    ciphertext = feistel_encrypt(plaintext, key)
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    # Decrypt the ciphertext
    decrypted_text = feistel_decrypt(ciphertext, key).decode()
    print(f"Decrypted text: {decrypted_text}")

if __name__ == "__main__":
    main()
