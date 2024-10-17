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
    
    # Save encrypted image
    with open('encrypted_image.bin', 'wb') as enc_file:
        enc_file.write(encrypted_image_data)

    print("Image encrypted successfully!")

# Decrypt image using AES
def decrypt_image(encrypted_image_path, symmetric_key):
    # Load encrypted image
    with open(encrypted_image_path, 'rb') as enc_file:
        encrypted_image_data = enc_file.read()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(symmetric_key[:16]), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt image data
    decrypted_image_data = decryptor.update(encrypted_image_data) + decryptor.finalize()

    # Save decrypted image
    with open('decrypted_image.png', 'wb') as dec_file:
        dec_file.write(decrypted_image_data)

    print("Image decrypted successfully!")

# Main function for user interaction
def main():
    # User choice
    choice = input("Do you want to (E)ncrypt or (D)ecrypt an image? (E/D): ").strip().upper()

    if choice == 'E':
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

        # Save keys (not strictly necessary for this example, but shown for completeness)
        with open('private_key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()))  # Fixed line

        with open('public_key.pem', 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))

    elif choice == 'D':
        # Load the private key for decryption
        with open('private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        # Load the public key (assume we have the public key of the party that encrypted)
        with open('public_key.pem', 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

        # Simulate sharing the public key and derive the shared symmetric key
        derived_key = derive_shared_key(private_key, public_key)

        # Get the path of the encrypted image
        encrypted_image_path = input("Enter the path of the encrypted image: ").strip()

        # Decrypt the image
        decrypt_image(encrypted_image_path, derived_key)

    else:
        print("Invalid choice! Please enter 'E' or 'D'.")

# Run the main function
if __name__ == "__main__":
    main()
