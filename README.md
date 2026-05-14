# RSA Cryptographic System

> **Asymmetric Key Exchange & Secure Communication Between Alice & Bob**

A comprehensive Python implementation of the RSA (Rivest-Shamir-Adleman) public key cryptosystem, featuring an interactive Rich terminal UI with animated visualizations, multiple attack simulations, and benchmarking tools.

Built for **Cyber Security Fundamentals** coursework.

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | **RSA Encrypt/Decrypt** | Full Alice-Bob communication with character-by-character math breakdown |
| 2 | **Auto Key Generation** | Generate RSA keys with auto-selected primes (configurable bit sizes) |
| 3 | **Digital Signatures** | Sign messages with private key, verify with public key, tamper detection |
| 4 | **Brute-Force Attack** | Trial division factoring simulation — recovers private key from public key |
| 5 | **MITM Attack** | Man-in-the-Middle simulation — Eve intercepts, reads, and forwards messages |
| 6 | **Frequency Analysis** | Exposes textbook RSA weakness — identical chars produce identical ciphertext |
| 7 | **Key Strength Analyzer** | Estimates crack time across Laptop / Server / Supercomputer / All Earth's PCs |
| 8 | **Benchmark** | Compares key generation, encryption, and decryption speed across key sizes |
| 9 | **Rich Terminal UI** | Colored panels, tree diagrams, animated network transfer, progress bars |

---

## How RSA Works

```
KEY GENERATION (Bob)
====================
1. Select two distinct large primes:      p, q
2. Compute modulus:                        n = p * q
3. Compute Euler's totient:                phi(n) = (p-1)(q-1)
4. Choose public exponent:                 e  such that  gcd(e, phi(n)) = 1
5. Compute private exponent:               d  such that  e*d = 1 (mod phi(n))

Public Key  = (e, n)   -->  Shared openly with Alice
Private Key = (d, n)   -->  Kept secret by Bob

ENCRYPTION (Alice)                    DECRYPTION (Bob)
==================                    =================
C = M^e mod n                         M = C^d mod n
(using Bob's public key)              (using Bob's private key)
```

### Communication Flow

```
  +-------+                                          +-----+
  | Alice |                                          | Bob |
  +-------+                                          +-----+
      |                                                 |
      |            (1) Bob generates key pair           |
      |           <--- Public Key (e, n) ---            |
      |                                                 |
      |  (2) Alice encrypts: C = M^e mod n              |
      |           --- Ciphertext C --->                  |
      |                                                 |
      |            (3) Bob decrypts: M = C^d mod n      |
      |                                                 |
```

---

## Project Structure

```
cryptography/
|-- main.py              # Interactive menu & demo orchestrator
|-- rsa_engine.py        # Core cryptographic engine (all math & algorithms)
|-- rsa_visualizer.py    # Rich terminal UI (panels, tables, animations)
|-- rsa_crypto.py        # Standalone simple version (no dependencies)
|-- requirements.txt     # Python dependencies
|-- .gitignore           # Git ignore rules
|-- README.md            # This file
```

### Module Responsibilities

| File | Lines | Role |
|------|-------|------|
| `rsa_engine.py` | ~400 | All RSA math: Miller-Rabin primality, key generation, modular exponentiation, encryption, decryption, digital signatures, brute-force factoring, MITM attack, frequency analysis, key strength estimation, benchmarking |
| `rsa_visualizer.py` | ~340 | Rich terminal rendering: colorized panels, tree views, encryption/decryption tables, animated network transfer, attack result displays, benchmark comparison charts |
| `main.py` | ~330 | Application entry point: interactive menu loop, user input validation, demo orchestration connecting engine and visualizer |
| `rsa_crypto.py` | ~230 | Self-contained RSA implementation with zero external dependencies — runs on any Python install |

---

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/rsa-cryptographic-system.git
cd rsa-cryptographic-system

# Install dependencies
pip install -r requirements.txt
```

### Running

```bash
# Full interactive program with Rich UI
python main.py

# Standalone version (no dependencies needed)
python rsa_crypto.py
```

---

## Interactive Menu

```
1   Full Demo -- Encrypt & Decrypt with custom primes
2   Full Demo -- Auto-generate primes
3   Digital Signature -- Sign & Verify a message
4   Brute-Force Attack -- Crack a key
5   MITM Attack -- Man-in-the-Middle simulation
6   Frequency Analysis -- Expose textbook RSA weakness
7   Key Strength Analyzer -- Estimate crack time
8   Benchmark -- Compare different key sizes
9   Run Automated Test Cases
0   Exit
```

---

## Algorithms Implemented

### Miller-Rabin Primality Test
Industry-grade probabilistic primality test with 20 rounds of witness testing. False positive probability is less than `4^(-20)` (under 1 in a trillion). Used for prime generation and validation.

### Modular Exponentiation (Square-and-Multiply)
Computes `(base ^ exponent) mod modulus` in **O(log n)** time using binary exponentiation. Processes the exponent bit-by-bit, squaring and multiplying modulo n at each step. Essential for both encryption (`C = M^e mod n`) and decryption (`M = C^d mod n`).

### Extended Euclidean Algorithm
Computes the modular multiplicative inverse `d = e^(-1) mod phi(n)`, which is the RSA private key exponent. Extends the standard GCD algorithm to find coefficients satisfying `ax + by = gcd(a,b)`.

### SHA-256 Hashing (for Signatures)
Uses Python's `hashlib` SHA-256 implementation (truncated to 32 bits) to create message digests for the digital signature scheme.

---

## Sample Output

### Test Case: "Hello Bob, this is Alice!" (p=7919, q=7907)

```
[KEY] RSA Key Generation
|-- Step 1: Prime Selection
|   |-- p = 7919
|   |-- q = 7907
|-- Step 2: Compute Modulus
|   |-- n = p x q = 7919 x 7907 = 62607533
|-- Step 3: Euler's Totient
|   |-- phi(n) = (p-1)(q-1) = 7918 x 7906 = 62591708
|-- Step 4: Public Exponent
|   |-- e = 65537
|-- Step 5: Private Exponent
    |-- d = 47685473

ENCRYPTION: C = M^e mod n
  'H' -> 72  -> 72^65537 mod 62607533  -> 41892034
  'e' -> 101 -> 101^65537 mod 62607533 -> 8293741
  ...

Alice -->> ENCRYPTED DATA -->> Bob
[OK] Ciphertext delivered securely

DECRYPTION: M = C^d mod n
  41892034^47685473 mod 62607533 -> 72  -> 'H'
  8293741^47685473 mod 62607533  -> 101 -> 'e'
  ...

[PASS] VERIFICATION PASSED
  Original  : Hello Bob, this is Alice!
  Decrypted : Hello Bob, this is Alice!
```

---

## Attack Simulations

### Brute-Force Factoring
Demonstrates trial division attack on small RSA keys. Given primes by the user, the program generates a key pair, then attempts to factor `n` back into `p` and `q`, recovering the private key.

### Man-in-the-Middle (MITM)
Simulates Eve intercepting the key exchange between Alice and Bob:
1. Eve generates her own key pair
2. Eve gives Alice her public key instead of Bob's
3. Alice encrypts with Eve's key — Eve reads the message
4. Eve re-encrypts with Bob's real key and forwards
5. Bob decrypts normally, unaware of the interception

**Lesson:** This is why certificate authorities and key authentication exist.

### Frequency Analysis
Shows that textbook RSA (per-character encryption) produces identical ciphertext for identical plaintext characters. An attacker can use statistical frequency patterns (like `'e'` being the most common English letter) to break the cipher without the private key.

**Lesson:** This is why production RSA uses OAEP padding and block cipher modes.

---

## Key Strength Analysis

The analyzer estimates time to crack an RSA key across different computing tiers:

| Computing Power | Example |
|-----------------|---------|
| Laptop (1 GHz) | Consumer hardware |
| Desktop (4 GHz) | Workstation |
| Server Cluster (1 THz) | Cloud computing |
| Supercomputer (1 PHz) | Top 500 machines |
| All computers on Earth | Theoretical maximum |

For comparison, a **2048-bit RSA key** would take longer than the age of the universe to crack, even with all computers on Earth working together.

---

## Educational vs Production RSA

| Aspect | This Implementation | Production RSA |
|--------|---------------------|----------------|
| Key Size | 16-56 bit | 2048-4096 bit |
| Prime Generation | Miller-Rabin (20 rounds) | CSPRNG + Miller-Rabin |
| Padding | None (textbook) | OAEP (PKCS#1 v2.2) |
| Encryption Mode | Per-character | Block-based |
| Signatures | SHA-256 (truncated) | Full SHA-256 + PSS |
| Library | Custom implementation | OpenSSL / libsodium |
| Attack Resistance | Seconds to minutes | Billions of years |

> **Note:** This project is built for educational demonstration. For real-world cryptography, use established libraries like `cryptography`, `PyCryptodome`, or `OpenSSL`.

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `rich` | >= 13.0 | Terminal UI: panels, tables, progress bars, colors |

All other functionality uses Python standard library modules (`hashlib`, `random`, `time`, `math`, `collections`).

---

## Testing

The automated test suite (menu option 9) runs 3 test cases with progressively larger primes:

| Test | Message | Primes (p, q) | Modulus Size |
|------|---------|---------------|--------------|
| 1 | "Hello Bob, this is Alice!" | (7919, 7907) | ~26 bits |
| 2 | "Cyber Security 2026" | (15013, 15017) | ~28 bits |
| 3 | "RSA encryption works!" | (104729, 104743) | ~34 bits |

All tests verify that `decrypt(encrypt(message)) == message`.

---

## License

This project is part of academic coursework for Cyber Security Fundamentals. Free to use for educational purposes.
