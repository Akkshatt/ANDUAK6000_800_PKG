import os
import json
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image
import numpy as np

def generate_keys():
    """Generate a private-public key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def image_to_bytes(image_path):
    """Convert an image to bytes."""
    try:
        image = Image.open(image_path)
        mode = image.mode
        image = image.convert("RGB")
        byte_data = np.array(image).tobytes()
        size = image.size
        return byte_data, size, mode
    except Exception as e:
        print(f"Error converting image to bytes: {e}")
        return None, None, None

def bytes_to_image(byte_data, size, mode, output_path):
    """Convert bytes back to an image and save it."""
    try:
        image = Image.frombytes(mode, size, byte_data)
        image.save(output_path)
    except Exception as e:
        print(f"Error converting bytes back to image: {e}")

def encrypt_data(public_key, data):
    """Encrypt data using a symmetric key (AES) derived from ECC."""
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)

    symmetric_key = hashes.Hash(hashes.SHA256())
    symmetric_key.update(shared_key)
    symmetric_key = symmetric_key.finalize()[:32]

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = iv + encryptor.update(data) + encryptor.finalize()

    return ciphertext, ephemeral_public_key

def decrypt_data(private_key, ephemeral_public_key, ciphertext):
    """Decrypt data using the symmetric key derived from ECC."""
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    symmetric_key = hashes.Hash(hashes.SHA256())
    symmetric_key.update(shared_key)
    symmetric_key = symmetric_key.finalize()[:32]

    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]

    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data

def save_image_metadata(size, mode, filename="image_metadata.json"):
    """Save image metadata to a JSON file."""
    metadata = {"size": size, "mode": mode}
    with open(filename, "w") as f:
        json.dump(metadata, f)

def load_image_metadata(filename="image_metadata.json"):
    """Load image metadata from a JSON file."""
    with open(filename, "r") as f:
        metadata = json.load(f)
    return tuple(metadata["size"]), metadata["mode"]

def main():
    private_key, public_key = generate_keys()

    action = input("Do you want to (e)ncrypt or (d)ecrypt an image? ").lower()
    image_path = input("Enter the path to the image: ")

    if action == 'e':
        byte_data, size, mode = image_to_bytes(image_path)
        if byte_data is None:
            return
        
        ciphertext, ephemeral_public_key = encrypt_data(public_key, byte_data)

        with open("encrypted_image.bin", "wb") as f:
            f.write(ciphertext)

        with open("ephemeral_public_key.pem", "wb") as f:
            f.write(ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        save_image_metadata(size, mode)
        print("Image encrypted and saved as 'encrypted_image.bin'.")

    elif action == 'd':
        with open("ephemeral_public_key.pem", "rb") as f:
            ephemeral_public_key = serialization.load_pem_public_key(f.read())

        with open("encrypted_image.bin", "rb") as f:
            ciphertext = f.read()

        size, mode = load_image_metadata()

        decrypted_data = decrypt_data(private_key, ephemeral_public_key, ciphertext)

        output_path = "decrypted_image.png"
        bytes_to_image(decrypted_data, size, mode, output_path)
        print(f"Image decrypted and saved as '{output_path}'.")

if __name__ == "__main__":
    main()
