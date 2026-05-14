"""
RSA Visualizer — Rich terminal UI for the RSA demonstration.
Beautiful panels, tables, animations, and step-by-step breakdowns.
"""

import sys
import io
import time

# Force UTF-8 output on Windows to support box-drawing characters
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.tree import Tree
from rich import box
from rich.align import Align
from rich.rule import Rule
from rich.live import Live
from rich.layout import Layout

console = Console(force_terminal=True)


def display_banner():
    """Display the main title banner."""
    banner = Text()
    banner.append("+======================================================+\n", style="bold cyan")
    banner.append("|               ", style="bold cyan")
    banner.append("RSA CRYPTOGRAPHIC SYSTEM", style="bold white")
    banner.append("               |\n", style="bold cyan")
    banner.append("|       Asymmetric Key Exchange & Communication        |\n", style="bold cyan")
    banner.append("|             ", style="bold cyan")
    banner.append("Alice <-> Bob Secure Channel", style="bold green")
    banner.append("             |\n", style="bold cyan")
    banner.append("+======================================================+", style="bold cyan")
    console.print()
    console.print(Align.center(banner))
    console.print()


def display_key_generation(params):
    """Display key generation results in a rich panel."""
    tree = Tree("[bold yellow][KEY] RSA Key Generation[/]", guide_style="cyan")

    primes = tree.add("[bold]Step 1: Prime Selection")
    primes.add(f"p = [cyan]{params['p']}[/]")
    primes.add(f"q = [cyan]{params['q']}[/]")

    modulus = tree.add("[bold]Step 2: Compute Modulus")
    modulus.add(f"n = p x q = [cyan]{params['p']}[/] x [cyan]{params['q']}[/] = [bold green]{params['n']}[/]")

    totient = tree.add("[bold]Step 3: Euler's Totient")
    totient.add(f"phi(n) = (p-1)(q-1) = [cyan]{params['p']-1}[/] x [cyan]{params['q']-1}[/] = [bold green]{params['phi_n']}[/]")

    pub = tree.add("[bold]Step 4: Public Exponent")
    pub.add(f"e = [bold green]{params['e']}[/]  (coprime with phi(n), gcd(e, phi(n)) = 1)")

    priv = tree.add("[bold]Step 5: Private Exponent")
    priv.add(f"d = [bold red]{params['d']}[/]  (modular inverse: e*d = 1 mod phi(n))")

    console.print(Panel(tree, title="[bold blue]BOB — Key Generation[/]",
                        border_style="blue", box=box.DOUBLE))

    # Key cards side by side
    pub_card = Panel(
        f"[bold]e = [green]{params['e']}[/]\nn = [green]{params['n']}[/][/]",
        title="[PUBLIC KEY]", border_style="green", box=box.ROUNDED
    )
    priv_card = Panel(
        f"[bold]d = [red]{params['d']}[/]\nn = [red]{params['n']}[/][/]",
        title="[PRIVATE KEY]", border_style="red", box=box.ROUNDED
    )
    console.print(Columns([pub_card, priv_card], equal=True, expand=True))


def animate_network_transfer(ciphertext):
    """Animate data flowing from Alice to Bob over the network."""
    console.print()
    frames = [
        "[green]Alice[/] --[bold yellow]>> ENCRYPTED DATA[/]-------------------- [dim]Bob[/]",
        "[green]Alice[/] ----[bold yellow]>> ENCRYPTED DATA[/]------------------  [dim]Bob[/]",
        "[green]Alice[/] ------[bold yellow]>> ENCRYPTED DATA[/]----------------  [dim]Bob[/]",
        "[green]Alice[/] --------[bold yellow]>> ENCRYPTED DATA[/]--------------  [dim]Bob[/]",
        "[green]Alice[/] ----------[bold yellow]>> ENCRYPTED DATA[/]------------  [dim]Bob[/]",
        "[green]Alice[/] ------------[bold yellow]>> ENCRYPTED DATA[/]----------  [dim]Bob[/]",
        "[green]Alice[/] --------------[bold yellow]>> ENCRYPTED DATA[/]--------  [dim]Bob[/]",
        "[green]Alice[/] ----------------[bold yellow]>> ENCRYPTED DATA[/]------  [dim]Bob[/]",
        "[green]Alice[/] ------------------[bold yellow]>> ENCRYPTED DATA[/]----  [dim]Bob[/]",
        "[green]Alice[/] --------------------[bold yellow]>> ENCRYPTED DATA[/]-- [bold cyan]Bob[/]",
    ]
    with Live(console=console, refresh_per_second=4) as live:
        for frame in frames:
            live.update(Align.center(Text.from_markup(frame)))
            time.sleep(0.4)
    console.print(Align.center(Text.from_markup(
        "[bold green][OK] Ciphertext delivered securely[/]"
    )))
    console.print()


def display_encryption_table(plaintext, numerical, ciphertext, public_key):
    """Show character-by-character encryption in a table."""
    e, n = public_key
    table = Table(title="[bold magenta]Encryption: C = M^e mod n[/]",
                  box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Char", style="bold white", justify="center")
    table.add_column("ASCII (M)", style="cyan", justify="center")
    table.add_column(f"M^{e} mod {n}", style="dim", justify="center")
    table.add_column("Cipher (C)", style="bold yellow", justify="center")

    for ch, m, c in zip(plaintext, numerical, ciphertext):
        display_char = repr(ch) if ch == ' ' else ch
        table.add_row(display_char, str(m), f"{m}^{e} mod {n}", str(c))

    console.print(Panel(table, title="[bold green]ALICE — Encryption[/]",
                        border_style="green", box=box.DOUBLE))


def display_decryption_table(ciphertext, decrypted_nums, decrypted_text, private_key):
    """Show character-by-character decryption in a table."""
    d, n = private_key
    table = Table(title="[bold magenta]Decryption: M = C^d mod n[/]",
                  box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Cipher (C)", style="bold yellow", justify="center")
    table.add_column(f"C^d mod {n}", style="dim", justify="center")
    table.add_column("ASCII (M)", style="cyan", justify="center")
    table.add_column("Char", style="bold white", justify="center")

    for c, m, ch in zip(ciphertext, decrypted_nums, decrypted_text):
        display_char = repr(ch) if ch == ' ' else ch
        table.add_row(str(c), f"{c}^{d} mod {n}", str(m), display_char)

    console.print(Panel(table, title="[bold cyan]BOB — Decryption[/]",
                        border_style="cyan", box=box.DOUBLE))


def display_signature_result(message, signature, msg_hash, verified, recovered, actual):
    """Display digital signature verification results."""
    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Property", style="bold")
    table.add_column("Value")
    table.add_row("Message", f"[white]{message}[/]")
    table.add_row("SHA-256 Hash (truncated)", f"[cyan]{msg_hash}[/]")
    table.add_row("Digital Signature", f"[yellow]{signature}[/]")
    table.add_row("Recovered Hash", f"[cyan]{recovered}[/]")
    table.add_row("Expected Hash", f"[cyan]{actual}[/]")

    status = "[bold green][VALID] Signature Authentic[/]" if verified \
        else "[bold red][INVALID] Signature Forged![/]"
    table.add_row("Verification", status)

    console.print(Panel(table, title="[bold magenta]Digital Signature[/]",
                        border_style="magenta", box=box.DOUBLE))


def display_attack_result(n, p, q, elapsed, attempts, success):
    """Display brute-force attack simulation results."""
    table = Table(box=box.ROUNDED, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Target n", f"[yellow]{n}[/]")
    table.add_row("Bit length of n", f"[cyan]{n.bit_length()} bits[/]")
    table.add_row("Attempts", f"[cyan]{attempts:,}[/]")
    table.add_row("Time", f"[cyan]{elapsed:.6f} seconds[/]")
    if success:
        table.add_row("Factors found", f"[red]p={p}, q={q}[/]")
        table.add_row("Status", "[bold red]!! KEY BROKEN !![/]")
    else:
        table.add_row("Status", "[bold green][OK] Key held -- factoring failed[/]")

    console.print(Panel(table, title="[bold red]Brute-Force Attack Simulation[/]",
                        border_style="red", box=box.DOUBLE))


def display_benchmark_table(results):
    """Display key size benchmark comparison table."""
    table = Table(title="[bold]Key Size Performance Comparison[/]",
                  box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Bits", style="bold cyan", justify="center")
    table.add_column("n (modulus)", style="dim", justify="right")
    table.add_column("Key Gen", style="green", justify="center")
    table.add_column("Encrypt", style="yellow", justify="center")
    table.add_column("Decrypt", style="red", justify="center")
    table.add_column("Correct", justify="center")

    for r in results:
        n_str = str(r['n'])
        if len(n_str) > 20:
            n_str = n_str[:17] + "..."
        table.add_row(
            str(r['bits']),
            n_str,
            f"{r['gen_time']*1000:.1f} ms",
            f"{r['enc_time']*1000:.2f} ms",
            f"{r['dec_time']*1000:.2f} ms",
            "[green]OK[/]" if r['correct'] else "[red]FAIL[/]"
        )

    console.print(Panel(table, title="[bold blue]Benchmark Results[/]",
                        border_style="blue", box=box.DOUBLE))


def display_verification(original, decrypted):
    """Display verification result with style."""
    if original == decrypted:
        console.print(Panel(
            f"[bold green][PASS] VERIFICATION PASSED[/]\n\n"
            f"  Original  : [white]{original}[/]\n"
            f"  Decrypted : [white]{decrypted}[/]\n\n"
            f"  [dim]Messages match -- RSA cycle is correct.[/]",
            border_style="green", box=box.DOUBLE
        ))
        return True
    else:
        console.print(Panel(
            f"[bold red][FAIL] VERIFICATION FAILED[/]\n\n"
            f"  Original  : [white]{original}[/]\n"
            f"  Decrypted : [white]{decrypted}[/]",
            border_style="red", box=box.DOUBLE
        ))
        return False





def display_frequency_analysis(analysis, ciphertext):
    """Display frequency analysis attack results."""
    # Plaintext frequency table
    if 'pt_freq' in analysis:
        pt_table = Table(title="[bold]Plaintext Character Frequency[/]",
                         box=box.SIMPLE_HEAVY, show_lines=True)
        pt_table.add_column("Char", style="bold white", justify="center")
        pt_table.add_column("Count", style="cyan", justify="center")
        pt_table.add_column("Freq %", style="green", justify="center")
        pt_table.add_column("Bar", style="green")

        for char, data in analysis['pt_freq'].items():
            bar = "#" * int(data['pct'] / 2)
            display_char = repr(char) if char == ' ' else char
            pt_table.add_row(display_char, str(data['count']),
                             f"{data['pct']:.1f}%", bar)
        console.print(pt_table)

    # Ciphertext frequency table
    ct_table = Table(title="[bold]Ciphertext Value Frequency[/]",
                     box=box.SIMPLE_HEAVY, show_lines=True)
    ct_table.add_column("Cipher Value", style="yellow", justify="center")
    ct_table.add_column("Count", style="cyan", justify="center")
    ct_table.add_column("Freq %", style="red", justify="center")
    ct_table.add_column("Bar", style="red")

    for val, data in analysis['ct_freq'].items():
        bar = "#" * int(data['pct'] / 2)
        ct_table.add_row(str(val), str(data['count']),
                         f"{data['pct']:.1f}%", bar)
    console.print(ct_table)

    # Analysis summary
    summary = (
        f"  Plaintext unique chars  : [cyan]{analysis.get('unique_pt', '?')}[/]\n"
        f"  Ciphertext unique values: [cyan]{analysis['unique_ct']}[/]\n"
        f"  Total characters        : [cyan]{analysis['ct_total']}[/]\n\n"
    )

    if analysis.get('pattern_match'):
        summary += (
            "  [bold red]!! VULNERABILITY DETECTED !![/]\n"
            "  The number of unique ciphertext values MATCHES the number\n"
            "  of unique plaintext characters. An attacker can use frequency\n"
            "  analysis to map ciphertext values back to plaintext characters.\n\n"
            "  [bold yellow]>> This is why textbook RSA (per-character) is insecure.[/]\n"
            "  [bold yellow]>> Production RSA uses padding (OAEP) and block modes.[/]\n"
        )

    console.print(Panel(summary, title="[bold red]Frequency Analysis Attack[/]",
                        border_style="red", box=box.DOUBLE))


def display_key_strength(analysis):
    """Display key strength analysis with crack time estimates."""
    table = Table(title="[bold]Estimated Time to Crack[/]",
                  box=box.SIMPLE_HEAVY, show_lines=True)
    table.add_column("Computing Power", style="bold cyan")
    table.add_column("Time to Factor n", style="yellow", justify="right")

    for name, time_str in analysis['crack_times'].items():
        table.add_row(name, time_str)

    # Header info
    n_str = str(analysis['n'])
    if len(n_str) > 30:
        n_str = n_str[:27] + "..."

    header = (
        f"  Key Size  : [cyan]{analysis['bits']} bits[/]\n"
        f"  Modulus n : [cyan]{n_str}[/]\n"
        f"  Operations needed (sqrt n) : [cyan]{analysis['ops_needed']:,}[/]\n"
    )

    console.print(Panel(
        header + "\n" + table.__rich_console__(console, console.options).__next__().text
        if False else header,
        title="[bold magenta]Key Strength Analysis[/]",
        border_style="magenta", box=box.DOUBLE
    ))
    console.print(table)


def show_menu():
    """Display the interactive menu."""
    console.print()
    console.print(Rule("[bold cyan]Menu[/]"))
    menu = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    menu.add_column("Option", style="bold yellow", justify="center")
    menu.add_column("Description", style="white")
    menu.add_row("1", "Full Demo -- Encrypt & Decrypt (custom or auto primes)")
    menu.add_row("2", "Digital Signature -- Sign & Verify a message")
    menu.add_row("3", "Brute-Force Attack -- Crack a key")
    menu.add_row("4", "Key Strength & Benchmark -- Analyze and compare key sizes")
    menu.add_row("5", "Run Automated Test Cases")
    menu.add_row("0", "Exit")
    console.print(Align.center(menu))
    console.print()

