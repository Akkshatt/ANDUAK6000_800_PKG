
```mermaid
graph TD;
    A[Sender]
    B[Receiver]
    
    subgraph ECC with Blinding, Masking, and Schnorr Signatures
        A1[Generate Key Pair]
        A2[Select Private Key]
        A3[Compute Public Key]
        A4[Encrypt Message]
        A5[Generate Blinding Factor]
        A6[Apply Masking]
        A7[Generate Schnorr Signature]
        A8[Send Encrypted Message and Signature]
    end
    
    subgraph ECC Decryption with Unmasking, Unblinding, and Signature Verification
        B1[Receive Encrypted Message and Signature]
        B2[Verify Schnorr Signature]
        B3[Remove Masking]
        B4[Unblind Encrypted Message]
        B5[Decrypt Message]
    end
    
    A --> A1
    A1 --> A2
    A2 --> A3
    A3 --> A4
    A4 --> A5
    A5 --> A6
    A6 --> A7
    A7 --> A8
    A8 --> B
    B --> B1
    B1 --> B2
    B2 --> B3
    B3 --> B4
    B4 --> B5

