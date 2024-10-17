from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Derive a symmetric key using ECDH
def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key[:32]  # Use first 32 bytes for AES-256 key

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
    # Load the private key for decryption
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load the public key (assume we have the public key of the party that encrypted)
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    # Simulate sharing the public key and derive the shared symmetric key
    derived_key = derive_shared_key(private_key, public_key)

    # Get the path of the encrypted image
    encrypted_image_path = input("Enter the path of the encrypted image (e.g., encrypted_image.bin): ").strip()

    # Decrypt the image
    decrypt_image(encrypted_image_path, derived_key)

# Run the main function
if __name__ == "__main__":
    main()
