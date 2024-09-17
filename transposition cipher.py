def create_grid(plaintext, num_cols):
    """Create a grid of plaintext with the specified number of columns."""
    grid = []
    for i in range(0, len(plaintext), num_cols):
        grid.append(plaintext[i:i + num_cols])
    return grid

def read_grid(grid, num_cols):
    """Read the grid column-wise to create the encrypted text."""
    encrypted_text = []
    for col in range(num_cols):
        for row in grid:
            if col < len(row):
                encrypted_text.append(row[col])
    return ''.join(encrypted_text)

def transposition_encrypt(plaintext, key):
    """Encrypt plaintext using columnar transposition cipher."""
    num_cols = len(key)
    grid = create_grid(plaintext, num_cols)
    
    # Generate a list of column indices sorted by key order
    key_order = sorted(range(len(key)), key=lambda x: key[x])
    
    # Read the grid based on the key order
    encrypted_text = read_grid(grid, num_cols)
    return encrypted_text

def transposition_decrypt(ciphertext, key):
    """Decrypt ciphertext using columnar transposition cipher."""
    num_cols = len(key)
    num_rows = len(ciphertext) // num_cols
    
    # Generate a list of column indices sorted by key order
    key_order = sorted(range(len(key)), key=lambda x: key[x])
    
    # Create an empty grid to fill in
    grid = ['' for _ in range(num_rows)]
    index = 0
    
    # Fill the grid according to key order
    for col in key_order:
        for row in range(num_rows):
            grid[row] += ciphertext[index]
            index += 1
    
    # Read the grid row-wise to get the decrypted text
    decrypted_text = ''.join([''.join(row) for row in grid])
    return decrypted_text

def main():
    plaintext = input("Enter the plaintext: ").replace(' ', '').upper()
    key = input("Enter the key (sequence of unique characters): ").upper()

    encrypted_text = transposition_encrypt(plaintext, key)
    print(f"Encrypted text: {encrypted_text}")

    decrypted_text = transposition_decrypt(encrypted_text, key)
    print(f"Decrypted text: {decrypted_text}")

if __name__ == "__main__":
    main()
