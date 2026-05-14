"""
RSA Asymmetric Key Cryptography - Alice & Bob Secure Communication
Course: Cyber Security Fundamentals
"""

import random


# SECTION 1: PRIME NUMBER UTILITIES

def is_prime(n):
    """Check whether a given number is prime."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_prime_in_range(low, high):
    """Generate a random prime number within [low, high]."""
    for _ in range(10000):
        candidate = random.randint(low, high)
        if candidate % 2 == 0 and candidate != 2:
            candidate += 1
        if candidate <= high and is_prime(candidate):
            return candidate
    raise ValueError(f"Could not find a prime in [{low}, {high}].")


# SECTION 2: RSA MATHEMATICAL FUNCTIONS

def gcd(a, b):
    """Compute GCD using the Euclidean Algorithm."""
    while b != 0:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """
    Compute modular inverse of e mod phi using Extended Euclidean Algorithm.
    Finds d such that (e * d) = 1 (mod phi).
    """
    original_phi = phi
    x0, x1 = 0, 1
    if phi == 1:
        return 0
    while e > 1:
        q = e // phi
        e, phi = phi, e % phi
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += original_phi
    return x1


def mod_exp(base, exponent, modulus):
    """
    Modular exponentiation: (base ^ exponent) mod modulus.
    Uses square-and-multiply for efficiency.
    Used for both encryption (C = M^e mod n) and decryption (M = C^d mod n).
    """
    result = 1
    base = base % modulus
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


# SECTION 3: RSA KEY GENERATION (Bob's Side)

def generate_keys(p=None, q=None):
    """
    Generate RSA public and private key pairs.
    Steps:
      1. Select two distinct primes p, q
      2. Compute n = p * q
      3. Compute phi(n) = (p-1)(q-1)
      4. Choose e: 1 < e < phi(n), gcd(e, phi(n)) = 1
      5. Compute d: (d * e) mod phi(n) = 1
    Returns: (public_key, private_key, params_dict)
    """
    if p is None:
        p = generate_prime_in_range(100, 999)
    if q is None:
        q = generate_prime_in_range(100, 999)

    if not is_prime(p):
        raise ValueError(f"p = {p} is NOT prime.")
    if not is_prime(q):
        raise ValueError(f"q = {q} is NOT prime.")
    if p == q:
        raise ValueError("p and q must be distinct primes.")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose public exponent e
    e = 2
    for candidate in [65537, 17, 7, 5, 3]:
        if candidate < phi_n and gcd(candidate, phi_n) == 1:
            e = candidate
            break

    # Compute private exponent d
    d = mod_inverse(e, phi_n)
    assert (e * d) % phi_n == 1, "Key generation error"

    public_key = (e, n)
    private_key = (d, n)
    params = {'p': p, 'q': q, 'n': n, 'phi_n': phi_n, 'e': e, 'd': d}
    return public_key, private_key, params


# SECTION 4: TEXT <-> NUMBER CONVERSION

def text_to_numbers(plaintext):
    """Convert plaintext string to list of ASCII integer values."""
    return [ord(char) for char in plaintext]


def numbers_to_text(numbers):
    """Convert list of integer values back to plaintext string."""
    return ''.join(chr(num) for num in numbers)


# SECTION 5: ENCRYPTION (Alice's Side)

def encrypt(plaintext, public_key):
    """
    Encrypt plaintext using RSA public key.
    Formula: C = M^e mod n  for each character M.
    """
    e, n = public_key
    numerical_values = text_to_numbers(plaintext)

    for i, val in enumerate(numerical_values):
        if val >= n:
            raise ValueError(
                f"Character '{plaintext[i]}' (value={val}) >= n={n}. "
                f"Use larger primes."
            )

    ciphertext = [mod_exp(M, e, n) for M in numerical_values]
    return ciphertext


# SECTION 6: DECRYPTION (Bob's Side)

def decrypt(ciphertext, private_key):
    """
    Decrypt ciphertext using RSA private key.
    Formula: M = C^d mod n  for each ciphertext block C.
    """
    d, n = private_key
    decrypted_values = [mod_exp(C, d, n) for C in ciphertext]
    return numbers_to_text(decrypted_values)


# SECTION 7: VERIFICATION

def verify_result(original, decrypted):
    """Verify decrypted message matches original plaintext."""
    if original == decrypted:
        print("  VERIFICATION PASSED: Decrypted output matches original.")
        return True
    else:
        print("  VERIFICATION FAILED!")
        print(f"    Original : '{original}'")
        print(f"    Decrypted: '{decrypted}'")
        return False


# SECTION 8: TEST RUNNER

def run_test_case(test_num, message, p=None, q=None):
    """Run a complete RSA encrypt-decrypt test case."""
    print(f"\n{'='*60}")
    print(f"  TEST CASE {test_num}")
    print(f"{'='*60}")
    try:
        print(f"\n  [BOB] Generating RSA key pair...")
        public_key, private_key, params = generate_keys(p, q)
        print(f"    Prime p         = {params['p']}")
        print(f"    Prime q         = {params['q']}")
        print(f"    Modulus n = p*q = {params['n']}")
        print(f"    Euler's phi(n)  = {params['phi_n']}")
        print(f"    Public Key  (e, n) = ({params['e']}, {params['n']})")
        print(f"    Private Key (d, n) = ({params['d']}, {params['n']})")

        print(f"\n  [ALICE] Original Message : \"{message}\"")
        numerical = text_to_numbers(message)
        print(f"  [ALICE] Numerical Format : {numerical}")
        ciphertext = encrypt(message, public_key)
        print(f"  [ALICE] Encrypted (sent) : {ciphertext}")

        decrypted = decrypt(ciphertext, private_key)
        print(f"\n  [BOB]   Decrypted Message : \"{decrypted}\"")
        print()
        verify_result(message, decrypted)
    except ValueError as ve:
        print(f"  ERROR: {ve}")
    except Exception as ex:
        print(f"  UNEXPECTED ERROR: {ex}")


# SECTION 9: MAIN PROGRAM

def main():
    """Main entry point with automated tests and interactive mode."""
    print("\n" + "=" * 60)
    print("  RSA ASYMMETRIC KEY CRYPTOGRAPHY")
    print("  Secure Communication Between Alice & Bob")
    print("=" * 60)

    # Part A: Automated Test Cases
    print("\n--- PART A: AUTOMATED TEST CASES ---")
    run_test_case(1, "Hello Bob!", p=61, q=53)
    run_test_case(2, "RSA 2026", p=101, q=103)
    run_test_case(3, "Cyber Security is important!", p=239, q=251)
    run_test_case(4, "Key: A1@#$", p=307, q=311)
    run_test_case(5, "Auto prime test!")

    # Part B: Interactive Mode
    print("\n\n--- PART B: INTERACTIVE MODE ---")
    while True:
        print("\n  Options:")
        print("    1. Enter custom primes and message")
        print("    2. Auto-generate primes, enter message only")
        print("    3. Exit")
        choice = input("\n  Enter choice (1/2/3): ").strip()

        if choice == '1':
            try:
                p = int(input("  Enter first prime (p) : "))
                q = int(input("  Enter second prime (q): "))
            except ValueError:
                print("  ERROR: Enter valid integers.")
                continue
            if not is_prime(p):
                print(f"  ERROR: {p} is not prime.")
                continue
            if not is_prime(q):
                print(f"  ERROR: {q} is not prime.")
                continue
            if p == q:
                print("  ERROR: p and q must differ.")
                continue
            if p * q < 128:
                print("  WARNING: n too small for ASCII. Use larger primes.")
                continue
            message = input("  Enter message: ")
            if not message:
                print("  ERROR: Empty message.")
                continue
            run_test_case("USER", message, p=p, q=q)

        elif choice == '2':
            message = input("  Enter message: ")
            if not message:
                print("  ERROR: Empty message.")
                continue
            run_test_case("USER", message)

        elif choice == '3':
            print("\n  Goodbye!\n")
            break
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    main()
