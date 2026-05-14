"""
RSA Cryptographic Engine — Core mathematical functions.
Includes Miller-Rabin primality, key generation, encryption,
decryption, digital signatures, and brute-force attack simulation.
"""

import random
import time
import hashlib


# ─────────────────────────────────────────────────────────────
# PRIME NUMBER UTILITIES
# ─────────────────────────────────────────────────────────────

def is_prime_basic(n):
    """Trial division primality test."""
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


def miller_rabin(n, k=20):
    """
    Miller-Rabin probabilistic primality test.
    Industry-grade algorithm used in real cryptographic systems.
    
    The probability of a false positive is at most 4^(-k).
    With k=20, that's less than 1 in a trillion.
    
    Algorithm:
        Write n-1 as 2^r * d (factor out powers of 2)
        For k rounds:
            Pick random witness a in [2, n-2]
            Compute x = a^d mod n
            If x == 1 or x == n-1, continue
            Square x up to r-1 times, checking for n-1
            If never found, n is composite
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite

    return True  # probably prime


def generate_prime(bits):
    """Generate a random prime number of approximately `bits` bit-length."""
    low = 2 ** (bits - 1)
    high = 2 ** bits - 1
    for _ in range(50000):
        candidate = random.randint(low, high) | 1  # ensure odd
        if miller_rabin(candidate):
            return candidate
    raise ValueError(f"Could not generate a {bits}-bit prime.")


# ─────────────────────────────────────────────────────────────
# RSA MATHEMATICAL CORE
# ─────────────────────────────────────────────────────────────

def gcd(a, b):
    """Euclidean algorithm for Greatest Common Divisor."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    """Extended Euclidean Algorithm to find modular inverse."""
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


def mod_exp(base, exp, mod):
    """
    Modular exponentiation using square-and-multiply.
    Computes (base ^ exp) mod mod efficiently in O(log exp) time.
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


# ─────────────────────────────────────────────────────────────
# RSA KEY GENERATION
# ─────────────────────────────────────────────────────────────

def generate_keys(p=None, q=None, bits=10):
    """
    Generate RSA key pair.
    If p and q are not provided, generates random primes of given bit size.
    Returns: (public_key, private_key, params_dict)
    """
    if p is None:
        p = generate_prime(bits)
    if q is None:
        q = generate_prime(bits)
        while q == p:
            q = generate_prime(bits)

    if not miller_rabin(p):
        raise ValueError(f"p={p} is not prime.")
    if not miller_rabin(q):
        raise ValueError(f"q={q} is not prime.")
    if p == q:
        raise ValueError("p and q must be distinct.")

    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Choose e
    e = 65537
    if e >= phi_n or gcd(e, phi_n) != 1:
        for candidate in [17, 7, 5, 3]:
            if candidate < phi_n and gcd(candidate, phi_n) == 1:
                e = candidate
                break

    d = mod_inverse(e, phi_n)
    assert (e * d) % phi_n == 1

    return (e, n), (d, n), {'p': p, 'q': q, 'n': n, 'phi_n': phi_n, 'e': e, 'd': d}


# ─────────────────────────────────────────────────────────────
# ENCRYPTION & DECRYPTION
# ─────────────────────────────────────────────────────────────

def text_to_numbers(text):
    """Convert text to list of ASCII values."""
    return [ord(c) for c in text]


def numbers_to_text(nums):
    """Convert list of ASCII values back to text."""
    return ''.join(chr(n) for n in nums)


def encrypt(plaintext, public_key):
    """Encrypt plaintext: C = M^e mod n for each character."""
    e, n = public_key
    nums = text_to_numbers(plaintext)
    for i, v in enumerate(nums):
        if v >= n:
            raise ValueError(f"Char '{plaintext[i]}' (val={v}) >= n={n}. Use larger primes.")
    return [mod_exp(m, e, n) for m in nums]


def decrypt(ciphertext, private_key):
    """Decrypt ciphertext: M = C^d mod n for each block."""
    d, n = private_key
    return numbers_to_text([mod_exp(c, d, n) for c in ciphertext])


# ─────────────────────────────────────────────────────────────
# DIGITAL SIGNATURES
# ─────────────────────────────────────────────────────────────

def compute_hash(message):
    """Compute a simple numeric hash of the message for signing."""
    h = hashlib.sha256(message.encode()).hexdigest()
    return int(h[:8], 16)  # Use first 32 bits as numeric hash


def sign_message(message, private_key):
    """
    Sign a message using the sender's PRIVATE key.
    Signature = Hash(M)^d mod n
    """
    d, n = private_key
    msg_hash = compute_hash(message)
    signature = mod_exp(msg_hash % n, d, n)
    return signature, msg_hash


def verify_signature(message, signature, public_key):
    """
    Verify a signature using the sender's PUBLIC key.
    Recovered_Hash = Signature^e mod n
    Valid if Recovered_Hash == Hash(M)
    """
    e, n = public_key
    recovered_hash = mod_exp(signature, e, n)
    actual_hash = compute_hash(message) % n
    return recovered_hash == actual_hash, recovered_hash, actual_hash


# ─────────────────────────────────────────────────────────────
# BRUTE-FORCE ATTACK SIMULATION
# ─────────────────────────────────────────────────────────────

def brute_force_factor(n):
    """
    Attempt to factor n by trial division.
    Returns (p, q, time_taken, attempts).
    This demonstrates WHY large primes make RSA secure.
    """
    start = time.time()
    attempts = 0
    for i in range(2, int(n ** 0.5) + 1):
        attempts += 1
        if n % i == 0:
            elapsed = time.time() - start
            return i, n // i, elapsed, attempts
    elapsed = time.time() - start
    return None, None, elapsed, attempts


# ─────────────────────────────────────────────────────────────
# KEY SIZE BENCHMARKING
# ─────────────────────────────────────────────────────────────

def benchmark_keygen(bits):
    """Benchmark key generation time for a given bit size."""
    start = time.time()
    pub, priv, params = generate_keys(bits=bits)
    gen_time = time.time() - start

    test_msg = "Test"
    start = time.time()
    ct = encrypt(test_msg, pub)
    enc_time = time.time() - start

    start = time.time()
    pt = decrypt(ct, priv)
    dec_time = time.time() - start

    return {
        'bits': bits, 'n': params['n'],
        'gen_time': gen_time, 'enc_time': enc_time, 'dec_time': dec_time,
        'correct': pt == test_msg
    }


# ─────────────────────────────────────────────────────────────
# MAN-IN-THE-MIDDLE (MITM) ATTACK SIMULATION
# ─────────────────────────────────────────────────────────────

def mitm_attack(message, bob_public, bob_private, eve_public, eve_private):
    """
    Simulate a Man-in-the-Middle attack.
    Eve intercepts the communication and substitutes her own public key.

    Flow:
      1. Alice thinks she has Bob's public key, but actually has Eve's
      2. Alice encrypts with Eve's public key
      3. Eve intercepts and decrypts with her private key
      4. Eve re-encrypts with Bob's real public key and forwards
      5. Bob decrypts normally, unaware of the interception
    """
    # Alice encrypts with what she thinks is Bob's key (actually Eve's)
    ciphertext_to_eve = encrypt(message, eve_public)

    # Eve intercepts and decrypts
    eve_decrypted = decrypt(ciphertext_to_eve, eve_private)

    # Eve re-encrypts with Bob's real public key and forwards
    ciphertext_to_bob = encrypt(eve_decrypted, bob_public)

    # Bob decrypts normally
    bob_decrypted = decrypt(ciphertext_to_bob, bob_private)

    return {
        'original': message,
        'ciphertext_intercepted': ciphertext_to_eve,
        'eve_decrypted': eve_decrypted,
        'ciphertext_forwarded': ciphertext_to_bob,
        'bob_decrypted': bob_decrypted,
        'eve_read_message': eve_decrypted == message,
        'bob_got_original': bob_decrypted == message,
    }


# ─────────────────────────────────────────────────────────────
# FREQUENCY ANALYSIS ATTACK
# ─────────────────────────────────────────────────────────────

def frequency_analysis(ciphertext, plaintext=None):
    """
    Perform frequency analysis on RSA ciphertext.
    In textbook RSA (per-character encryption), identical plaintext
    characters always produce identical ciphertext values.
    An attacker can exploit this pattern to break the cipher.

    Returns character frequency data for both plaintext and ciphertext.
    """
    from collections import Counter

    # Ciphertext frequency
    ct_freq = Counter(ciphertext)
    ct_total = len(ciphertext)
    ct_analysis = {val: {'count': count, 'pct': count / ct_total * 100}
                   for val, count in ct_freq.most_common()}

    result = {
        'ct_freq': ct_analysis,
        'ct_total': ct_total,
        'unique_ct': len(ct_freq),
    }

    # Plaintext frequency (if available, for comparison)
    if plaintext:
        pt_freq = Counter(plaintext)
        pt_analysis = {char: {'count': count, 'pct': count / len(plaintext) * 100}
                       for char, count in pt_freq.most_common()}
        result['pt_freq'] = pt_analysis
        result['unique_pt'] = len(pt_freq)
        result['plaintext'] = plaintext

        # Check if frequency patterns match (attack success indicator)
        result['pattern_match'] = (len(ct_freq) == len(pt_freq))

    return result


# ─────────────────────────────────────────────────────────────
# KEY STRENGTH ANALYZER
# ─────────────────────────────────────────────────────────────

def analyze_key_strength(n):
    """
    Analyze the strength of an RSA key by estimating the time to
    crack it at various computing speeds.

    Estimates based on trial division operations needed (~sqrt(n)).
    """
    import math
    bits = n.bit_length()
    # Approximate operations needed to factor n via trial division
    ops_needed = int(math.isqrt(n))

    # Operations per second for different computing tiers
    speeds = {
        'Laptop (1 GHz)':          1_000_000_000,
        'Desktop (4 GHz)':         4_000_000_000,
        'Server Cluster (1 THz)':  1_000_000_000_000,
        'Supercomputer (1 PHz)':   1_000_000_000_000_000,
        'All computers on Earth':  1_000_000_000_000_000_000,
    }

    results = {}
    for name, ops_per_sec in speeds.items():
        seconds = ops_needed / ops_per_sec
        results[name] = format_time(seconds)

    return {
        'bits': bits,
        'n': n,
        'ops_needed': ops_needed,
        'crack_times': results,
    }


def format_time(seconds):
    """Format seconds into human-readable time string."""
    if seconds < 0.001:
        return f"{seconds*1_000_000:.1f} microseconds"
    if seconds < 1:
        return f"{seconds*1000:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    if seconds < 86400 * 365:
        return f"{seconds/86400:.1f} days"
    years = seconds / (86400 * 365.25)
    if years < 1000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years/1000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years/1_000_000:.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years/1_000_000_000:.1f} billion years"
    return f"{years/1_000_000_000_000:.1f} trillion years"
