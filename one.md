# ECC Implementations

## 1. Normal Implementation of ECC

```mermaid
graph TD;
    A[User Input] --> B[Generate Key ];
    B --> C[Perform ECC Encryption];
    C --> D[Send Ciphertext];
    D --> E[Perform ECC Decryption];
    E --> F[Return Plaintext];
