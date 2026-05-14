# RSA Asymmetric Key Cryptography — Assignment Report

## Secure Communication Between Alice & Bob

**Course:** Principles and Practices of Cryptography  
**Topic:** Public Key Cryptography (RSA Algorithm) & Advanced Attack Simulations  
**Date:** May 2026

---

## 1. Introduction & Theory

### What is RSA?
RSA (Rivest–Shamir–Adleman) is a foundational **asymmetric encryption algorithm** that utilizes two mathematically linked keys — a **public key** for encryption and a **private key** for decryption. Unlike symmetric cryptography (where both parties share one secret key), RSA allows secure communication without ever transmitting a shared secret over the network.

### The Asymmetric Advantage
In symmetric systems, the shared secret key must be transmitted securely — creating a classic chicken-and-egg problem. RSA solves this by allowing Bob to publish his public key openly. Anyone (including Alice) can encrypt a message with it, but **only Bob** can decrypt it using his mathematically linked private key. 

### Mathematical Foundation
RSA's security rests on the **Integer Factorization Problem**. Given a modulus `n = p × q` (where `p` and `q` are large primes), it is computationally infeasible for an adversary to recover the original prime factors from `n` alone.

---

## 2. Implemented Architecture

The project was developed in Python with a modular, professional architecture focusing on both cryptographic accuracy and educational visualization. 

### System Modules
1. **`rsa_engine.py`**: The cryptographic backend. Contains all mathematical implementations including Miller-Rabin primality testing, square-and-multiply modular exponentiation, the Extended Euclidean algorithm, digital signatures (SHA-256), and brute-force factoring simulations.
2. **`rsa_visualizer.py`**: The presentation layer. Utilizes the `rich` library to render animated network transfers, encryption/decryption state tables, attack workflows, and colored terminal user interfaces.
3. **`main.py`**: The orchestration layer. Manages the interactive menu loop, handles user input validation, and connects the cryptographic engine to the visualizer.

---

## 3. Core Features & Demonstrations

The application features 5 core interactive modules designed to demonstrate different aspects of the RSA lifecycle:

### Feature 1: Alice-Bob Full Communication Flow
Demonstrates the complete lifecycle of an RSA transaction.
- Bob generates an RSA key pair (either via auto-generated primes or custom user input).
- Alice receives the public key `(e, n)` and encrypts her message. The system displays a table showing the character-by-character math (`C = M^e mod n`).
- An animated network transfer visually represents the ciphertext crossing the wire.
- Bob receives the ciphertext and decrypts it using his private key `(d, n)`, proving that the original message is recovered.

### Feature 2: Digital Signatures & Non-Repudiation
Demonstrates how RSA can be run in reverse to provide authentication.
- Bob hashes a message using SHA-256.
- He encrypts the hash with his **private key** to create a signature.
- Alice uses Bob's **public key** to decrypt the signature and verify the hash.
- **Tamper Test**: The system simulates altering the message in transit, successfully demonstrating how the signature verification fails, thus ensuring data integrity.

### Feature 3: Brute-Force Factoring Attack
Demonstrates why key size matters.
- The user inputs two small primes to generate a weak RSA key.
- The system plays the role of an attacker who intercepts the public key modulus `n`.
- Using trial division, the system attacks `n`, successfully factoring it back into `p` and `q`.
- The attacker then computes the Euler totient and reconstructs the private key `d`, completely breaking the encryption.

### Feature 4: Key Strength & Performance Benchmarking
Provides real-world context to cryptographic key lengths.
- Evaluates a generated key and estimates the time required to crack it across various computing tiers (from a single laptop up to a hypothetical cluster of all computers on Earth).
- Runs an automated benchmark suite across bit sizes (8-bit up to 28-bit), measuring key generation, encryption, and decryption latency.
- Highlights the exponential growth in brute-force difficulty as bit size increases.

### Feature 5: Automated Test Suite
A regression and correctness suite that runs predefined end-to-end communication scenarios using progressively larger primes (up to 34-bit modulus). Ensures that `decrypt(encrypt(message)) == message` holds true under diverse conditions.

---

## 4. Cryptographic Implementation Details

### Miller-Rabin Primality Test
Instead of basic trial division, the engine uses the industry-standard Miller-Rabin probabilistic test with 20 rounds of verification. This reduces the false-positive probability to less than $4^{-20}$, ensuring robust prime generation.

### Square-and-Multiply Exponentiation
Directly computing $M^e$ for large exponents would cause memory overflow. The implementation utilizes binary modular exponentiation, computing the result bit-by-bit in $O(\log e)$ time.

### Extended Euclidean Algorithm
To compute the private exponent $d$ (where $e \times d \equiv 1 \pmod{\phi(n)}$), the system extends the standard GCD algorithm to find the modular multiplicative inverse efficiently.

---

## 5. Security Analysis & Educational Value

### Textbook RSA vs. Production RSA
This system implements **Textbook RSA**, meaning it performs deterministic, per-character encryption. While mathematically identical to production RSA, it lacks padding.

| Aspect | This Implementation | Production RSA |
|--------|---------------------|----------------|
| **Padding** | None (Deterministic) | OAEP (PKCS#1 v2.2) |
| **Key Size** | 16-bit to 56-bit | 2048-bit to 4096-bit |
| **Prime Gen** | Miller-Rabin | CSPRNG + Miller-Rabin |
| **Block Mode**| Per-Character | Padded Blocks |

### Lessons Learned
1. **The Necessity of Padding:** Textbook RSA is vulnerable to frequency analysis and chosen-plaintext attacks. Real systems must inject randomness (padding) into the plaintext before encryption.
2. **Computational Complexity:** The benchmarking module proves that while encryption time grows linearly with key size, the difficulty of factoring $n$ grows exponentially, highlighting the fundamental premise of asymmetric security.
3. **Authentication:** Encryption provides confidentiality, but digital signatures provide authenticity and integrity. Both are required for a secure channel.

---

## 6. Conclusion

This project successfully fulfills the assignment requirements by building a mathematically sound, fully functional RSA cryptosystem from scratch. By extending the requirements to include a professional terminal UI, digital signatures, brute-force simulations, and benchmarking tools, the project serves as a comprehensive educational platform for understanding both the strengths and vulnerabilities of public-key cryptography.
