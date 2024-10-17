import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
import binascii

# Load the image
def load_image(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    return np.array(img)

# Convert the pixel values to hex
def pixels_to_hex(pixels):
    hex_values = []
    for row in pixels:
        hex_row = []
        for pixel in row:
            hex_color = '#{:02x}{:02x}{:02x}'.format(pixel[0], pixel[1], pixel[2])
            hex_row.append(hex_color)
        hex_values.append(hex_row)
    return hex_values

# Encrypt hex values using ECC
def encrypt_hex_values(hex_values, public_key):
    encrypted_hex_values = []
    for row in hex_values:
        encrypted_row = []
        for hex_value in row:
            hex_bytes = binascii.unhexlify(hex_value[1:])
            signature = public_key.sign(hex_bytes, ec.ECDSA(hashes.SHA256()))
            encrypted_hex = binascii.hexlify(signature).decode('utf-8')
            encrypted_row.append('#' + encrypted_hex[:6])  # Using first 6 characters for RGB
        encrypted_hex_values.append(encrypted_row)
    return encrypted_hex_values

# Convert hex values back to pixels
def hex_to_pixels(hex_values):
    pixels = []
    for row in hex_values:
        pixel_row = []
        for hex_value in row:
            r = int(hex_value[1:3], 16)
            g = int(hex_value[3:5], 16)
            b = int(hex_value[5:7], 16)
            pixel_row.append([r, g, b])
        pixels.append(pixel_row)
    return np.array(pixels, dtype=np.uint8)

# Save the pixel array as an image
def save_image(pixels, output_path):
    img = Image.fromarray(pixels)
    img.save(output_path)

# Main function
def main():
    # Take input from user
    input_image_path = input("Enter the path of the input image: ")
    output_image_path = input("Enter the path for the output encrypted image: ")

    # Load image
    pixels = load_image(input_image_path)
    
    # Convert pixels to hex
    hex_values = pixels_to_hex(pixels)

    # Generate ECC keys
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Encrypt hex values
    encrypted_hex_values = encrypt_hex_values(hex_values, public_key)

    # Convert encrypted hex values back to pixels
    encrypted_pixels = hex_to_pixels(encrypted_hex_values)

    # Save encrypted image
    save_image(encrypted_pixels, output_image_path)

if __name__ == '__main__':
    main()
