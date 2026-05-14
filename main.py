"""
RSA Cryptographic System -- Main Program
Demonstrates asymmetric key exchange between Alice and Bob.
Run: python main.py
"""

import sys
import io

# Force UTF-8 output on Windows
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from rich.progress import Progress, SpinnerColumn, TextColumn
from rsa_engine import (
    miller_rabin, generate_keys, encrypt, decrypt,
    text_to_numbers, sign_message, verify_signature,
    brute_force_factor, benchmark_keygen, mod_exp,
    mitm_attack, analyze_key_strength
)
from rsa_visualizer import (
    console, display_banner, display_key_generation,
    animate_network_transfer, display_encryption_table,
    display_decryption_table, display_signature_result,
    display_attack_result, display_benchmark_table,
    display_verification, show_menu,
    display_mitm_result, display_key_strength
)


# ─────────────────────────────────────────────────────────────
# DEMO FUNCTIONS
# ─────────────────────────────────────────────────────────────

def run_full_demo(message, p=None, q=None, bits=16):
    """Run the complete Alice-Bob communication demo."""
    with Progress(SpinnerColumn(), TextColumn("[bold blue]Bob is generating RSA keys..."),
                  console=console, transient=True) as progress:
        progress.add_task("keygen", total=None)
        public_key, private_key, params = generate_keys(p, q, bits=bits)

    display_key_generation(params)

    console.print()
    numerical = text_to_numbers(message)
    ciphertext = encrypt(message, public_key)
    display_encryption_table(message, numerical, ciphertext, public_key)

    animate_network_transfer(ciphertext)

    d, n = private_key
    decrypted_nums = [mod_exp(c, d, n) for c in ciphertext]
    decrypted = decrypt(ciphertext, private_key)
    display_decryption_table(ciphertext, decrypted_nums, decrypted, private_key)

    console.print()
    display_verification(message, decrypted)


def run_signature_demo(message, bits=16):
    """Demonstrate digital signature signing and verification."""
    console.print("\n[bold magenta]-- Digital Signature Demo --[/]\n")

    public_key, private_key, params = generate_keys(bits=bits)
    display_key_generation(params)

    signature, msg_hash = sign_message(message, private_key)
    verified, recovered, actual = verify_signature(message, signature, public_key)
    display_signature_result(message, signature, msg_hash, verified, recovered, actual)

    console.print("\n[bold red]-- Tampering Test --[/]\n")
    tampered = message + " (TAMPERED)"
    verified2, recovered2, actual2 = verify_signature(tampered, signature, public_key)
    display_signature_result(tampered, signature, msg_hash, verified2, recovered2, actual2)


def run_attack_demo(p, q):
    """Run brute-force factoring attack on a key generated from given primes."""
    console.print("\n[bold red]-- Brute-Force Attack Simulation --[/]\n")

    public_key, private_key, params = generate_keys(p, q)
    display_key_generation(params)

    n = params['n']
    console.print(f"\n[dim]Attacker intercepts public key: n = {n} ({n.bit_length()} bits)[/]")
    console.print(f"[dim]Attacker tries to factor n to recover p and q...[/]\n")

    with Progress(SpinnerColumn(), TextColumn("[bold red]Brute-forcing..."),
                  console=console, transient=True) as progress:
        progress.add_task("attack", total=None)
        found_p, found_q, elapsed, attempts = brute_force_factor(n)

    success = found_p is not None
    display_attack_result(n, found_p, found_q, elapsed, attempts, success)

    if success:
        console.print("\n[bold red]Attacker reconstructs the private key from factors:[/]")
        _, cracked_priv, cracked_params = generate_keys(found_p, found_q)
        console.print(f"  Recovered d = [red]{cracked_params['d']}[/]")
        console.print(f"  Actual    d = [red]{params['d']}[/]")
        if cracked_params['d'] == params['d']:
            console.print("  [bold red]!! Private key fully recovered -- key is BROKEN !![/]")
        console.print()


def run_mitm_demo(message):
    """Run Man-in-the-Middle attack simulation."""
    console.print("\n[bold red]-- Man-in-the-Middle Attack --[/]\n")

    console.print("[bold cyan]Bob's Key Pair:[/]")
    bob_pub, bob_priv, bob_params = generate_keys(bits=16)
    display_key_generation(bob_params)

    console.print("\n[bold red]Eve's Key Pair (attacker):[/]")
    eve_pub, eve_priv, eve_params = generate_keys(bits=16)
    display_key_generation(eve_params)

    console.print("\n[dim]Eve intercepts the key exchange and gives Alice her own public key...[/]\n")

    result = mitm_attack(message, bob_pub, bob_priv, eve_pub, eve_priv)
    display_mitm_result(result)


def run_key_strength_and_benchmark(p, q):
    """Run key strength analysis followed by benchmark comparison."""
    # Part 1: Key Strength Analysis
    console.print("\n[bold magenta]-- Key Strength Analyzer --[/]\n")

    public_key, private_key, params = generate_keys(p, q)
    display_key_generation(params)

    analysis = analyze_key_strength(params['n'])
    console.print()
    display_key_strength(analysis)

    # 2048-bit RSA comparison
    console.print("\n[bold yellow]For comparison -- estimated 2048-bit RSA crack time:[/]")
    fake_2048 = analyze_key_strength(2**2048)
    display_key_strength(fake_2048)

    # Part 2: Benchmark across key sizes
    console.print("\n[bold blue]-- Key Size Benchmark --[/]\n")
    bit_sizes = [8, 10, 12, 16, 20, 24, 28]
    results = []

    with Progress(SpinnerColumn(), TextColumn("[bold]Benchmarking {task.fields[bits]}-bit keys..."),
                  console=console) as progress:
        task = progress.add_task("bench", total=len(bit_sizes), bits="")
        for bits in bit_sizes:
            progress.update(task, bits=f"{bits}")
            try:
                r = benchmark_keygen(bits)
                results.append(r)
            except Exception:
                results.append({'bits': bits, 'n': 0, 'gen_time': 0,
                                'enc_time': 0, 'dec_time': 0, 'correct': False})
            progress.advance(task)

    display_benchmark_table(results)

    # Factoring difficulty comparison
    console.print("\n[bold yellow]Factoring Difficulty:[/]")
    for r in results:
        if r['n'] > 0 and r['bits'] <= 28:
            _, _, elapsed, attempts = brute_force_factor(r['n'])
            bar_len = min(int(attempts / 50), 40)
            bar = "#" * bar_len
            console.print(f"  [cyan]{r['bits']:>3}-bit[/] | {attempts:>10,} attempts | "
                          f"[red]{bar}[/] {elapsed:.4f}s")


def run_automated_tests():
    """Run predefined test cases with larger primes."""
    tests = [
        ("Hello Bob, this is Alice!", 7919, 7907, "Large 4-digit primes"),
        ("Cyber Security 2026", 15013, 15017, "5-digit primes"),
        ("RSA encryption works!", 104729, 104743, "6-digit primes"),
    ]

    for i, (msg, p, q, desc) in enumerate(tests, 1):
        console.print(f"\n{'='*60}")
        console.print(f"[bold cyan]TEST {i}: {desc}[/]  --  primes ({p}, {q})")
        console.print(f"{'='*60}")
        try:
            run_full_demo(msg, p=p, q=q)
        except Exception as e:
            console.print(f"[bold red]ERROR: {e}[/]")


# ─────────────────────────────────────────────────────────────
# MAIN INTERACTIVE LOOP
# ─────────────────────────────────────────────────────────────

def main():
    """Main entry point with interactive menu."""
    display_banner()

    while True:
        show_menu()
        choice = console.input("[bold yellow]  Enter choice -> [/]").strip()

        if choice == '1':
            # Ask: custom primes or auto-generated?
            mode = console.input("  [cyan]Use custom primes? (y/n): [/]").strip().lower()

            if mode == 'y':
                try:
                    p = int(console.input("  [cyan]Enter prime p: [/]"))
                    q = int(console.input("  [cyan]Enter prime q: [/]"))
                except ValueError:
                    console.print("[red]  Invalid number.[/]")
                    continue
                if not miller_rabin(p) or not miller_rabin(q):
                    console.print("[red]  One or both numbers are not prime.[/]")
                    continue
                if p == q:
                    console.print("[red]  p and q must be different.[/]")
                    continue
                if p * q < 128:
                    console.print("[red]  n=p*q too small. Use larger primes.[/]")
                    continue
                msg = console.input("  [cyan]Enter message: [/]")
                if not msg:
                    console.print("[red]  Empty message.[/]")
                    continue
                run_full_demo(msg, p=p, q=q)
            else:
                msg = console.input("  [cyan]Enter message: [/]")
                if not msg:
                    console.print("[red]  Empty message.[/]")
                    continue
                console.print("  [dim]Auto-generating 16-bit primes...[/]")
                run_full_demo(msg, bits=16)

        elif choice == '2':
            msg = console.input("  [cyan]Enter message to sign: [/]")
            if not msg:
                console.print("[red]  Empty message.[/]")
                continue
            run_signature_demo(msg, bits=16)

        elif choice == '3':
            try:
                p = int(console.input("  [cyan]Enter prime p: [/]"))
                q = int(console.input("  [cyan]Enter prime q: [/]"))
            except ValueError:
                console.print("[red]  Invalid number.[/]")
                continue
            if not miller_rabin(p) or not miller_rabin(q):
                console.print("[red]  One or both numbers are not prime.[/]")
                continue
            if p == q:
                console.print("[red]  p and q must be different.[/]")
                continue
            run_attack_demo(p, q)

        elif choice == '4':
            msg = console.input("  [cyan]Enter message for MITM demo: [/]")
            if not msg:
                console.print("[red]  Empty message.[/]")
                continue
            run_mitm_demo(msg)

        elif choice == '5':
            try:
                p = int(console.input("  [cyan]Enter prime p: [/]"))
                q = int(console.input("  [cyan]Enter prime q: [/]"))
            except ValueError:
                console.print("[red]  Invalid number.[/]")
                continue
            if not miller_rabin(p) or not miller_rabin(q):
                console.print("[red]  One or both numbers are not prime.[/]")
                continue
            run_key_strength_and_benchmark(p, q)

        elif choice == '6':
            run_automated_tests()

        elif choice == '0':
            console.print("\n[bold green]  Goodbye![/]\n")
            break

        else:
            console.print("[red]  Invalid choice.[/]")


if __name__ == "__main__":
    main()
