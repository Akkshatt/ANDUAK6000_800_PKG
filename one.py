from ecdsa import SigningKey, VerifyingKey, NIST256p
from hashlib import sha256

def generate_keys():
    """Generate a private-public key pair using NIST256p curve."""
    private_key = SigningKey.generate(curve=NIST256p)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def encrypt(public_key, plaintext):
    """Encrypt a plaintext message using the recipient's public key."""
    # Generate a random private key (ephemeral key)
    ephemeral_private_key = SigningKey.generate(curve=NIST256p)
    ephemeral_public_key = ephemeral_private_key.get_verifying_key()

    # Perform key agreement: shared secret = ephemeral_private_key * public_key
    shared_secret = ephemeral_private_key.privkey.secret_multiplier * public_key.pubkey.point

    # Hash the shared secret to derive a symmetric key
    symmetric_key = sha256(shared_secret.to_bytes()).digest()

    # Encrypt the message using the symmetric key (simple XOR for demonstration)
    ciphertext = bytes([m ^ k for m, k in zip(plaintext.encode(), symmetric_key)])

    return ephemeral_public_key.to_string(), ciphertext

def decrypt(private_key, ephemeral_public_key_bytes, ciphertext):
    """Decrypt a ciphertext using the recipient's private key."""
    # Reconstruct the ephemeral public key from bytes
    ephemeral_public_key = VerifyingKey.from_string(ephemeral_public_key_bytes, curve=NIST256p)

    # Perform key agreement: shared secret = private_key * ephemeral_public_key
    shared_secret = private_key.privkey.secret_multiplier * ephemeral_public_key.pubkey.point

    # Hash the shared secret to derive a symmetric key
    symmetric_key = sha256(shared_secret.to_bytes()).digest()

    # Decrypt the message using the symmetric key (simple XOR for demonstration)
    plaintext = bytes([c ^ k for c, k in zip(ciphertext, symmetric_key)]).decode()

    return plaintext

def main():
    choice = input("Do you want to (e)ncrypt or (d)ecrypt a message? ")

    if choice == 'e':
        # Generate recipient's key pair
        private_key, public_key = generate_keys()
        print(f"Public Key: {public_key.to_string().hex()}")
        print(f"Private Key: {private_key.to_string().hex()}")

        # Message to be encrypted
        message = input("Enter the message to encrypt: ")

        # Encrypt the message
        ephemeral_public_key_bytes, ciphertext = encrypt(public_key, message)
        print(f"Ephemeral Public Key: {ephemeral_public_key_bytes.hex()}")
        print(f"Ciphertext: {ciphertext.hex()}")

    elif choice == 'd':
        # Reconstruct the recipient's private key from input
        private_key_hex = input("Enter the recipient's private key (hex): ")
        private_key = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=NIST256p)

        # Ephemeral public key and ciphertext from input
        ephemeral_public_key_hex = input("Enter the ephemeral public key (hex): ")
        ephemeral_public_key_bytes = bytes.fromhex(ephemeral_public_key_hex)

        ciphertext_hex = input("Enter the ciphertext (hex): ")
        ciphertext = bytes.fromhex(ciphertext_hex)

        # Decrypt the message
        decrypted_message = decrypt(private_key, ephemeral_public_key_bytes, ciphertext)
        print(f"Decrypted message: {decrypted_message}")

    else:
        print("Invalid choice. Please select 'e' for encryption or 'd' for decryption.")

if __name__ == "__main__":
    main()
