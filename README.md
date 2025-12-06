# hsm-lite

A C++ project aimed at emulating the core functionalities of a **Hardware Security Module (HSM)** in order to explore and better understand how these devices operate internally.

## Overview

- The goal of hsm-lite is to provide a simplified, software-based environment that mimics an HSM’s core services. 
- The project is being developed following **Test-Driven Development (TDD)** principles to ensure correctness,  maintainability, and clarity of design.
- hsm-lite is developed in C++17, uses **OpenSSL** as a cryptographic backend and employs **Catch2** as its testing framework.

## Implemented Features

### Key Management

Implements basic key management functionalities to simulate an HSM’s keystore:

- Key injection
- Key erasure
- Key updating
- Key retrieval

### Cryptographic Features

#### <ins>Hashing</ins>

Allows for key hashing using the SHA-2 family of hashing algorithms:

- SHA-224  
- SHA-256  
- SHA-384  
- SHA-512  

#### <ins>Symmetric Cryptography</ins>

Supports AES encryption and decryption with multiple key sizes:

- AES-128  
- AES-192  
- AES-256

And multiple cipher modes:

- ECB
- CBC
- CTR

#### <ins>Asymmetric Cryptography</ins>

##### RSA 

Used for **key pair generation**, **encryption**, **decryption**, **signing** and **verifying**:
- RSA-2048
- RSA-4096

##### ECDSA

Used for **key pair generation**, **signing** and **verifying**:
- P-256
- P-384
- P-521

## Future Work

Future planned additions include:

- Persistent key storage
- Further hashing algorithms and symmetric ciphers/cipher modes
- HSM lifecycle management 
- User and role management access control
- Hardware integration with devices like Raspberry Pi for hybrid HSM experimentation
