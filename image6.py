import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode

def pad(data):
    while len(data) % 16 != 0:
        data += b' '
    return data

def encrypt_image_component(component, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(component.tobytes())
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_component = np.frombuffer(encrypted_data, dtype=np.uint8).reshape(component.shape)
    return encrypted_component

def decrypt_image_component(encrypted_component, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = encrypted_component.tobytes()
    decrypted_data = cipher.decrypt(encrypted_data)
    decrypted_component = np.frombuffer(decrypted_data, dtype=np.uint8).reshape(encrypted_component.shape)
    return decrypted_component

def generate_keys():
    key1 = get_random_bytes(16)
    key2 = get_random_bytes(16)
    key3 = get_random_bytes(16)
    return key1, key2, key3

def ecc_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

def ecc_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)
    return decrypted_data

def encrypt_image(image_path, public_key):
    image = cv2.imread(image_path)
    red, green, blue = cv2.split(image)
    
    key1, key2, key3 = generate_keys()
    
    encrypted_red = encrypt_image_component(red, key1)
    encrypted_green = encrypt_image_component(green, key2)
    encrypted_blue = encrypt_image_component(blue, key3)
    
    encrypted_image = cv2.merge((encrypted_red, encrypted_green, encrypted_blue))
    
    secret_key = key1 + key2 + key3
    encrypted_secret_key = ecc_encrypt(secret_key, public_key)
    
    return encrypted_image, encrypted_secret_key, secret_key

def decrypt_image(encrypted_image, encrypted_secret_key, private_key):
    secret_key = ecc_decrypt(encrypted_secret_key, private_key)
    key1, key2, key3 = secret_key[:16], secret_key[16:32], secret_key[32:]
    
    encrypted_red, encrypted_green, encrypted_blue = cv2.split(encrypted_image)
    
    decrypted_red = decrypt_image_component(encrypted_red, key1)
    decrypted_green = decrypt_image_component(encrypted_green, key2)
    decrypted_blue = decrypt_image_component(encrypted_blue, key3)
    
    decrypted_image = cv2.merge((decrypted_red, decrypted_green, decrypted_blue))
    return decrypted_image

# Generate ECC key pair
private_key = ECC.generate(curve='P-256')
public_key = private_key.public_key()

# Get user input for image path
image_path = input("Enter the path of the image to encrypt: ")

# Encrypt the image
encrypted_image, encrypted_secret_key, secret_key = encrypt_image(image_path, public_key)
cv2.imwrite('encrypted_image.png', encrypted_image)

# Decrypt the image
decrypted_image = decrypt_image(encrypted_image, encrypted_secret_key, private_key)
cv2.imwrite('decrypted_image.png', decrypted_image)
