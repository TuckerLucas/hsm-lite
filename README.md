# hsm-lite

A C++ project aimed at emulating the core functionalities of a **Hardware Security Module (HSM)** in order to explore and better understand how these devices operate internally.

## Overview

- The goal of hsm-lite is to provide a simplified, software-based environment that mimics an HSM’s core services. 
- The project is being developed following **Test-Driven Development (TDD)** principles to ensure correctness,  maintainability, and clarity of design.
- hsm-lite is developed in C++17, uses **OpenSSL** as a cryptographic backend and employs **GoogleTest** as its testing framework.

## Implemented Features

### Key Management

Implements basic key management functionalities to simulate an HSM’s keystore:

- Key injection
- Key erasure
- Key updating
- Key retrieval

### Cryptographic Features

#### Hashing

Allows for key hashing using the SHA-2 family of hashing algorithms:

- SHA-224  
- SHA-256  
- SHA-384  
- SHA-512  

#### Symmetric Cryptography

Supports AES encryption and decryption with multiple key sizes:

- AES-128  
- AES-192  
- AES-256

And multiple cipher modes:

- ECB
- CBC
- CTR

#### Asymmetric Cryptography (In Progress)

Currently under development. Implemented and planned features include:

- RSA key pair generation (implemented)
- RSA encryption (in progress)
- RSA decryption (in progress)
- RSA signing and verification (next step)

## Future Work

Future planned additions include:

- ECDSA asymmetric cryptography
- Persistent key storage
- Further hashing algorithms and symmetric ciphers/cipher modes
- HSM lifecycle management 
- User and role management access control
- Hardware integration with devices like Raspberry Pi for hybrid HSM experimentation