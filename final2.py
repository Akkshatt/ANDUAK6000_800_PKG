from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from tinyec import registry
import os
import secrets
from PIL import Image
import io

# Helper Functions for MAES
def aes_key_expansion(key):
    # Simple key expansion for AES (128-bit key schedule generation)
    cipher = AES.new(key, AES.MODE_ECB)
    key_schedule = [key[i:i+16] for i in range(0, len(key), 16)]
    while len(key_schedule) < 11:
        key_schedule.append(cipher.encrypt(key_schedule[-1]))
    return key_schedule

def shift_columns(state):
    # Simplified example of shift columns operation (placeholder)
    return state

def sub_bytes(state):
    # Simplified example of sub bytes operation (placeholder)
    return state

def add_round_key(state, key_schedule, round):
    return bytes(a ^ b for a, b in zip(state, key_schedule[round]))

def maes_encrypt_block(block, key):
    state = bytearray(block)
    key_schedule = aes_key_expansion(key)
    state = add_round_key(state, key_schedule, 0)

    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_columns(state)
        state = add_round_key(state, key_schedule, round)

    state = sub_bytes(state)
    state = shift_columns(state)
    state = add_round_key(state, key_schedule, 10)
    return bytes(state)

def maes_encrypt(image_data, key):
    encrypted_data = b""
    padded_data = pad(image_data, 16)  # Ensure the entire data is padded correctly
    for block_start in range(0, len(padded_data), 16):
        block = padded_data[block_start:block_start + 16]
        encrypted_data += maes_encrypt_block(block, key)
    return encrypted_data

def maes_decrypt_block(block, key):
    state = bytearray(block)
    key_schedule = aes_key_expansion(key)
    state = add_round_key(state, key_schedule, 10)

    for round in range(9, 0, -1):
        state = shift_columns(state)  # Inverse shift columns (placeholder)
        state = sub_bytes(state)      # Inverse sub bytes (placeholder)
        state = add_round_key(state, key_schedule, round)

    state = shift_columns(state)  # Inverse shift columns (placeholder)
    state = sub_bytes(state)      # Inverse sub bytes (placeholder)
    state = add_round_key(state, key_schedule, 0)
    return bytes(state)

def maes_decrypt(encrypted_data, key):
    decrypted_data = b""
    for block_start in range(0, len(encrypted_data), 16):
        block = encrypted_data[block_start:block_start + 16]
        decrypted_data += maes_decrypt_block(block, key)
    return unpad(decrypted_data, 16)  # Unpad after the entire data is decrypted

# Helper Functions for ECC
def generate_ecc_keypair():
    curve = registry.get_curve('brainpoolP256r1')
    priv_key = secrets.randbelow(curve.field.n)
    pub_key = priv_key * curve.g
    return priv_key, pub_key

def ecc_encrypt(pub_key, plaintext_bytes):
    curve = pub_key.curve
    k = secrets.randbelow(curve.field.n)
    c1 = k * curve.g
    c2 = k * pub_key
    
    plaintext_int = int.from_bytes(plaintext_bytes, byteorder='big')
    c2_x_int = int(c2.x)
    
    encrypted_key_int = plaintext_int ^ c2_x_int
    encrypted_key = encrypted_key_int.to_bytes((encrypted_key_int.bit_length() + 7) // 8, byteorder='big')
    return c1, encrypted_key

def ecc_decrypt(priv_key, c1, encrypted_key):
    curve = c1.curve
    c2 = priv_key * c1
    
    encrypted_key_int = int.from_bytes(encrypted_key, byteorder='big')
    c2_x_int = int(c2.x)
    
    decrypted_key_int = encrypted_key_int ^ c2_x_int
    decrypted_key = decrypted_key_int.to_bytes((decrypted_key_int.bit_length() + 7) // 8, byteorder='big')
    return decrypted_key

# Hybrid Encryption
def hybrid_encrypt(image_data):
    # Generate ECC keypair for encryption
    priv_key, pub_key = generate_ecc_keypair()
    
    # Generate random AES key
    aes_key = os.urandom(16)
    
    # Encrypt the AES key using ECC
    c1, encrypted_key = ecc_encrypt(pub_key, aes_key)
    
    # Encrypt the image data using MAES
    encrypted_image = maes_encrypt(image_data, aes_key)
    
    return priv_key, c1, encrypted_key, encrypted_image

# Hybrid Decryption
def hybrid_decrypt(priv_key, c1, encrypted_key, encrypted_image):
    # Decrypt the AES key using ECC
    decrypted_aes_key = ecc_decrypt(priv_key, c1, encrypted_key)
    
    # Decrypt the image data using MAES
    decrypted_image = maes_decrypt(encrypted_image, decrypted_aes_key)
    
    return decrypted_image

# Function to load image and convert to bytes
def load_image(image_path):
    with Image.open(image_path) as img:
        byte_arr = io.BytesIO()
        img.save(byte_arr, format='PNG')
        return byte_arr.getvalue(), img.size

# Function to save bytes as image
def save_image(image_data, size, output_path):
    img = Image.open(io.BytesIO(image_data))
    img = img.resize(size)
    img.save(output_path)

# Usage Example
if __name__ == "__main__":
    # Input image path
    input_image_path = input("Enter the path of the image to encrypt: ")
    
    # Load the image and convert to bytes
    image_data, image_size = load_image(input_image_path)
    
    # Encrypt the image
    priv_key, c1, encrypted_key, encrypted_image = hybrid_encrypt(image_data)

    # Save the encrypted image data to a file
    encrypted_image_path = "encrypted_image.bin"
    with open(encrypted_image_path, "wb") as f:
        f.write(encrypted_image)
    
    # Decrypt the image
    decrypted_image = hybrid_decrypt(priv_key, c1, encrypted_key, encrypted_image)
    
    # Verify the decryption
    assert image_data == decrypted_image, "Decryption failed, original and decrypted data do not match!"
    
    # Save the decrypted image
    output_image_path = "decrypted_image.png"
    save_image(decrypted_image, image_size, output_image_path)
    
    print(f"Original image data: {image_data[:64]}")
    print(f"Encrypted image data saved as: {encrypted_image_path}")
    print(f"Decrypted image data saved as: {output_image_path}")
