from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Generate ECC key pair
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Derive a symmetric key using ECDH
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key[:32]  # Use first 32 bytes for AES-256 key

# Encrypt image using AES
def encrypt_image(image_path, symmetric_key):
    # Load image
    with open(image_path, 'rb') as img_file:
        image_data = img_file.read()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(symmetric_key[:16]), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt image data
    encrypted_image_data = encryptor.update(image_data) + encryptor.finalize()

    # Save encrypted image as binary file
    with open('encrypted_image.bin', 'wb') as enc_file:
        enc_file.write(encrypted_image_data)

    # Save encrypted image as PNG file
    with open('encrypted_image.png', 'wb') as enc_png_file:
        enc_png_file.write(encrypted_image_data)

    print("Image encrypted successfully!")

# Main function for user interaction
def main():
    # Generate ECC keys
    private_key, public_key = generate_ecc_key_pair()

    # Get image path from user
    image_path = input("Enter the path of the image to encrypt: ").strip()

    # Create a random symmetric key for AES (256 bits)
    symmetric_key = os.urandom(32)  # 32 bytes for AES-256

    # Simulate sharing the public key and derive the shared symmetric key
    peer_public_key = public_key  # In a real scenario, this would come from the other party
    derived_key = derive_shared_key(private_key, peer_public_key)

    # Encrypt the image
    encrypt_image(image_path, derived_key)

    # Save keys (optional, for decryption)
    with open('private_key.pem', 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))

    with open('public_key.pem', 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))

# Run the main function
if __name__ == "__main__":
    main()
