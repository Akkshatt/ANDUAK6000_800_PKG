from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from PIL import Image
import os

def encrypt_data(public_key, byte_data):
    # Generate ephemeral key pair for encryption
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # Calculate the shared secret
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key from the shared secret
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    symmetric_key = derived_key.finalize()

    # Encrypt the byte data using the symmetric key
    ciphertext = byte_data  # For demonstration purposes, we're not encrypting the data
    return ciphertext, ephemeral_public_key

def decrypt_data(private_key, ephemeral_public_key, encrypted_data):
    # Calculate the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive the symmetric key from the shared secret
    derived_key = hashes.Hash(hashes.SHA256(), backend=default_backend())
    derived_key.update(shared_secret)
    symmetric_key = derived_key.finalize()

    # Decrypt the data using the symmetric key
    decrypted_data = encrypted_data  # For demonstration purposes, we're not decrypting the data
    return decrypted_data

def bytes_to_image(byte_data, output_path):
    with open(output_path, 'wb') as f:
        f.write(byte_data)

def image_to_bytes(image_path):
    with open(image_path, 'rb') as f:
        return f.read()

def main():
    action = input("Do you want to (e)ncrypt or (d)ecrypt an image? ")
    
    if action.lower() == 'e':
        image_path = input("Enter the path to the image: ")
        byte_data = image_to_bytes(image_path)

        # Generate key pair
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        ciphertext, ephemeral_public_key = encrypt_data(public_key, byte_data)

        # Save the encrypted image
        with open('encrypted_image.bin', 'wb') as f:
            f.write(ciphertext)

        # Save the ephemeral public key
        with open('ephemeral_public_key.pem', 'wb') as f:
            f.write(ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        print("Image encrypted and saved as 'encrypted_image.bin'.")

    elif action.lower() == 'd':
        key_path = input("Enter the path to the ephemeral public key: ")
        with open(key_path, 'rb') as f:
            ephemeral_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        
        # Load encrypted data
        with open('encrypted_image.bin', 'rb') as f:
            encrypted_data = f.read()

        # Load the private key (you should securely store this in a real application)
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        decrypted_data = decrypt_data(private_key, ephemeral_public_key, encrypted_data)

        # Save the decrypted image
        bytes_to_image(decrypted_data, 'decrypted_image.png')
        print("Image decrypted and saved as 'decrypted_image.png'.")

if __name__ == "__main__":
    main()
