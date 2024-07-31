from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def generate_key(key_size=16):
    #Generate a secure random key.
    return get_random_bytes(key_size)

def encrypt(plaintext, key):
    # Generate a random IV for CBC mode
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Pad the plaintext and encrypt it
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    # Return the IV and ciphertext concatenated together
    return iv + ciphertext

def decrypt(iv_ciphertext, key):
    # Extract the IV and ciphertext
    iv = iv_ciphertext[:AES.block_size]
    ciphertext = iv_ciphertext[AES.block_size:]
    # Create a cipher object with the same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt and unpad the plaintext
    decrypted_data = cipher.decrypt(ciphertext)
    unpadded_data = unpad(decrypted_data, AES.block_size)
    
    return unpadded_data.decode()
def encryption():
    plaintext = input("Please enter the plaintext: ").strip()
    # Securely generate a key (normally, you'd securely store and manage this key)
    key = generate_key()
    print("Encryption Key (hex):", key.hex())
    # Encrypt the plaintext
    iv_ciphertext = encrypt(plaintext, key)
    print("Ciphertext (hex):", iv_ciphertext.hex())
    
def decryption():
    iv_ciphertext_hex = input("Please enter the IV and ciphertext (in hex format): ").strip()
    iv_ciphertext = bytes.fromhex(iv_ciphertext_hex)
    # The key should be the same as used during encryption
    key_hex = input("Please enter the key (in hex format): ").strip()
    key = bytes.fromhex(key_hex)
    # Decrypt the ciphertext
    plaintext = decrypt(iv_ciphertext, key)
    # Print the decrypted plaintext
    print("Decrypted Plaintext:", plaintext)

print("AES Encryption and Decryption")
mode = input("Please choose 'encryption' or 'decryption': ").strip().lower()

if mode == 'encryption':
    encryption()

elif mode == 'decryption':
    decryption()

else:
    print("Invalid option. Please choose 'encryption' or 'decryption'.")
