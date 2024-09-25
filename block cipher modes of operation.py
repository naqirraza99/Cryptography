# This script demonstrates various modes of AES encryption using the PyCryptodome library.
# Modes implemented include:
# 1. Electronic Codebook (ECB) Mode
# 2. Cipher Block Chaining (CBC) Mode
# 3. Cipher Feedback (CFB) Mode
# 4. Output Feedback (OFB) Mode
# 5. Counter (CTR) Mode
# Each function generates a random key and IV (Initialization Vector) where applicable,
# encrypts the provided plaintext, and then decrypts it to demonstrate the effectiveness
# of the encryption. The ciphertext and decrypted text are printed in a hexadecimal format.
#pip install pycryptodome


try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
except ImportError:
    print("pycryptodome is not installed. Please install it using 'pip install pycryptodome'.")
    exit()

# Function for Electronic Codebook (ECB) Mode
def ecb_mode(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)

    plaintext_bytes = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(plaintext_bytes)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

    print(f"ECB Ciphertext: {ciphertext.hex()}")
    print(f"ECB Decrypted: {decrypted.decode('utf-8')}\n")

# Function for Cipher Block Chaining (CBC) Mode
def cbc_mode(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext_bytes = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(plaintext_bytes)
    decrypted = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), AES.block_size)

    print(f"CBC Ciphertext: {ciphertext.hex()}")
    print(f"CBC Decrypted: {decrypted.decode('utf-8')}\n")

# Function for Cipher Feedback (CFB) Mode
def cfb_mode(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)

    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    decrypted = AES.new(key, AES.MODE_CFB, iv).decrypt(ciphertext)

    print(f"CFB Ciphertext: {ciphertext.hex()}")
    print(f"CFB Decrypted: {decrypted.decode('utf-8')}\n")

# Function for Output Feedback (OFB) Mode
def ofb_mode(plaintext):
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB, iv)

    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    decrypted = AES.new(key, AES.MODE_OFB, iv).decrypt(ciphertext)

    print(f"OFB Ciphertext: {ciphertext.hex()}")
    print(f"OFB Decrypted: {decrypted.decode('utf-8')}\n")

# Function for Counter (CTR) Mode
def ctr_mode(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)

    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    decrypted = AES.new(key, AES.MODE_CTR, nonce=cipher.nonce).decrypt(ciphertext)

    print(f"CTR Ciphertext: {ciphertext.hex()}")
    print(f"CTR Decrypted: {decrypted.decode('utf-8')}\n")

# Example usage
plaintext = "This is a test for block cipher modes."
ecb_mode(plaintext)
cbc_mode(plaintext)
cfb_mode(plaintext)
ofb_mode(plaintext)
ctr_mode(plaintext)
