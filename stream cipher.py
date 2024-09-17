import os

class SimpleStreamCipher:
    def __init__(self, key):
        """Initialize the cipher with a given key."""
        self.key = key
        self.key_stream = self.generate_key_stream(len(key))
    
    def generate_key_stream(self, length):
        """Generate a pseudo-random key stream of the specified length."""
        # Using a simple XOR-based pseudo-random number generator
        # for demonstration purposes
        key_stream = bytearray(length)
        state = int.from_bytes(self.key.encode(), 'little')
        for i in range(length):
            state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
            key_stream[i] = (state >> 16) & 0xFF
        return key_stream
    
    def encrypt(self, plaintext):
        """Encrypt the plaintext using the key stream."""
        plaintext_bytes = plaintext.encode()
        ciphertext = bytearray(len(plaintext_bytes))
        for i in range(len(plaintext_bytes)):
            ciphertext[i] = plaintext_bytes[i] ^ self.key_stream[i]
        return ciphertext
    
    def decrypt(self, ciphertext):
        """Decrypt the ciphertext using the key stream."""
        plaintext = bytearray(len(ciphertext))
        for i in range(len(ciphertext)):
            plaintext[i] = ciphertext[i] ^ self.key_stream[i]
        return plaintext.decode()

def main():
    key = input("Enter the key (use a short key for simplicity): ")
    plaintext = input("Enter the plaintext: ")
    
    # Initialize the cipher
    cipher = SimpleStreamCipher(key)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    
    # Decrypt the ciphertext
    decrypted_text = cipher.decrypt(ciphertext)
    print(f"Decrypted text: {decrypted_text}")

if __name__ == "__main__":
    main()
