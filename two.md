```mermaid
graph TD;
    A[User Input] --> B[Generate Key (Private/Public)];
    B --> C[Generate Random Blinding Factor];
    C --> D[Perform ECC Encryption (Masking & Blinding)];
    D --> E[Send Ciphertext];
    E --> F[Perform ECC Decryption (Unmask & Unblind)];
    F --> G[Return Plaintext];
