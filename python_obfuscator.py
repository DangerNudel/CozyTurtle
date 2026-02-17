#!/usr/bin/env python3
"""
Python Script Obfuscator + Analyzer - Threat Hunting Lab Tool
Author: Jason (Higher Echelon, Inc.)
Purpose: Generate obfuscated Python samples and deobfuscate/analyze them for
         detection rule development and analyst training.
Target:  Python 3.6+

─── OBFUSCATE ────────────────────────────────────────────────────────────────
  python3 python_obfuscator.py -f script.py -t all
  python3 python_obfuscator.py -f script.py -t b64
  python3 python_obfuscator.py --inline 'import socket; ...' -t all
  python3 python_obfuscator.py -f script.py -t multi --layers 3
  python3 python_obfuscator.py -f script.py -t all -o ./samples/

─── ANALYZE / DEOBFUSCATE ────────────────────────────────────────────────────
  python3 python_obfuscator.py --analyze -f obfuscated.py
  python3 python_obfuscator.py --analyze --inline 'exec(bytes.fromhex("696d706f7274..."))'
  python3 python_obfuscator.py --analyze -f obfuscated.py --report
  python3 python_obfuscator.py --analyze -f obfuscated.py --report -o ./reports/

─── BATCH ────────────────────────────────────────────────────────────────────
  python3 python_obfuscator.py --batch ./samples/ --quiet
  python3 python_obfuscator.py --batch ./samples/ --recursive --report -o ./reports/

─── DIFF ─────────────────────────────────────────────────────────────────────
  python3 python_obfuscator.py --diff baseline.json ./new_samples/
  python3 python_obfuscator.py --diff ./old/ ./new/ --report -o ./diffs/

─── WATCH ────────────────────────────────────────────────────────────────────
  python3 python_obfuscator.py --watch ./samples/ --interval 30
  python3 python_obfuscator.py --watch ./samples/ --interval 10 --alert-only
  python3 python_obfuscator.py --watch ./samples/ --report -o ./watch_logs/

─── OTHER ────────────────────────────────────────────────────────────────────
  python3 python_obfuscator.py --list-techniques
"""

import argparse, base64, codecs, csv, hashlib, io, json, os
import re, random, signal, string, struct, sys, time, zlib
from datetime import datetime
from textwrap import dedent

# ─────────────────────────────────────────────────────────────────────────────
# SHARED UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def rand_var(length=None):
    length = length or random.randint(4, 9)
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

def to_hex_str(s):
    """Return Python hex string e.g. '696d706f7274...'"""
    return s.encode().hex()

def to_b64(s):
    return base64.b64encode(s.encode()).decode()

def to_unicode_escapes(s):
    return ''.join(f'\\u{ord(c):04x}' for c in s)

def to_bytearray(s):
    return list(s.encode())

def rot13(s):
    return codecs.encode(s, 'rot_13')

def split_string_randomly(s, min_parts=2, max_parts=5):
    n = random.randint(min_parts, min(max_parts, max(2, len(s) // 2)))
    indices = sorted(random.sample(range(1, len(s)), min(n - 1, len(s) - 1)))
    parts, prev = [], 0
    for idx in indices:
        parts.append(s[prev:idx]); prev = idx
    parts.append(s[prev:])
    return [p for p in parts if p]

def strip_comments(code):
    """Strip # comments and shebang from Python source."""
    lines = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped.startswith('#'): continue
        # Inline comment removal (naive — avoids regex complexity in strings)
        if '#' in line:
            # Only strip if # appears outside a string (simple heuristic)
            in_str, q = False, None
            for i, c in enumerate(line):
                if c in ('"', "'") and not in_str:
                    in_str, q = True, c
                elif in_str and c == q:
                    in_str = False
                elif not in_str and c == '#':
                    line = line[:i].rstrip()
                    break
        if line.strip():
            lines.append(line)
    return '\n'.join(lines)

def get_payload(code):
    return strip_comments(code).strip()

def print_banner():
    print(dedent("""
    ╔══════════════════════════════════════════════════════════════╗
    ║      Python Obfuscator + Analyzer — Threat Hunt Lab Tool     ║
    ║                    Python 3.6+ Compatible                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """))

def print_section(title, content, note=None):
    w = 66
    print(f"\n{'═'*w}\n  {title}\n{'═'*w}")
    print(content)
    if note: print(f"\n  [Hunt Target] {note}")


# ─────────────────────────────────────────────────────────────────────────────
# OBFUSCATION TECHNIQUES
# ─────────────────────────────────────────────────────────────────────────────

def technique_base64(code):
    """
    exec(base64.b64decode(b'...'))
    Optionally split the b64 string across variables.
    Detection: base64.b64decode inside exec/eval, import base64 without legitimate use
    """
    payload = get_payload(code)
    encoded = to_b64(payload)
    if random.choice([True, False]):
        parts  = split_string_randomly(encoded, 2, 4)
        vnames = [rand_var() for _ in parts]
        lines  = [f"{v} = '{p}'" for v, p in zip(vnames, parts)]
        concat = ' + '.join(vnames)
        lines.append(f"import base64; exec(base64.b64decode({concat}))")
        body   = '\n'.join(lines)
    else:
        body = f"import base64; exec(base64.b64decode(b'{encoded}'))"
    return body


def technique_hex(code):
    """
    exec(bytes.fromhex('696d706f7274...'))
    Detection: bytes.fromhex inside exec, long hex string literals
    """
    payload = get_payload(code)
    hex_str = to_hex_str(payload)
    if random.choice([True, False]):
        parts  = split_string_randomly(hex_str, 2, 4)
        vnames = [rand_var() for _ in parts]
        lines  = [f"{v} = '{p}'" for v, p in zip(vnames, parts)]
        concat = ' + '.join(vnames)
        lines.append(f"exec(bytes.fromhex({concat}))")
        body   = '\n'.join(lines)
    else:
        body = f"exec(bytes.fromhex('{hex_str}'))"
    return body


def technique_zlib(code):
    """
    exec(zlib.decompress(base64.b64decode(b'...')))
    Detection: zlib.decompress + base64 combo inside exec — rare in legitimate code
    """
    payload  = get_payload(code)
    compressed = zlib.compress(payload.encode(), level=9)
    encoded    = base64.b64encode(compressed).decode()
    v1 = rand_var(); v2 = rand_var()
    body = (
        f"import zlib, base64\n"
        f"{v1} = b'{encoded}'\n"
        f"{v2} = zlib.decompress(base64.b64decode({v1}))\n"
        f"exec({v2})"
    )
    return body


def technique_vars(code):
    """
    Split the source code string across many variables, join and exec.
    Detection: many short string vars + exec(''.join([...])) pattern
    """
    payload = get_payload(code)
    parts   = split_string_randomly(payload, 4, 8)
    vnames  = [rand_var() for _ in parts]
    lines   = [f"{v} = {repr(p)}" for v, p in zip(vnames, parts)]
    joined  = ', '.join(vnames)
    lines.append(f"exec(''.join([{joined}]))")
    return '\n'.join(lines)


def technique_unicode(code):
    """
    exec('\\u0069\\u006d\\u0070...')   (unicode escape string)
    Detection: exec/eval with a dense unicode-escaped string literal
    """
    payload    = get_payload(code)
    uni_str    = to_unicode_escapes(payload)
    if random.choice([True, False]):
        v    = rand_var()
        body = f'{v} = "{uni_str}"\nexec({v})'
    else:
        body = f'exec("{uni_str}")'
    return body


def technique_rot13(code):
    """
    import codecs; exec(codecs.decode('...', 'rot_13'))
    Detection: codecs.decode with 'rot_13' or 'rot13' inside exec
    """
    payload  = get_payload(code)
    rotated  = rot13(payload)
    if random.choice([True, False]):
        v    = rand_var()
        body = (f"import codecs\n"
                f"{v} = {repr(rotated)}\n"
                f"exec(codecs.decode({v}, 'rot_13'))")
    else:
        body = f"import codecs; exec(codecs.decode({repr(rotated)}, 'rot_13'))"
    return body


def technique_bytearray(code):
    """
    exec(bytearray([105,109,112,...]).decode())
    Detection: exec(bytearray([...]).decode()) with large integer list
    """
    payload  = get_payload(code)
    arr      = to_bytearray(payload)
    if random.choice([True, False]):
        v    = rand_var()
        body = f"{v} = bytearray({arr})\nexec({v}.decode())"
    else:
        body = f"exec(bytearray({arr}).decode())"
    return body


def technique_lambda(code):
    """
    (lambda _: exec(_))('...')  — wraps base64 decode in lambda chain
    Detection: lambda chains ending in exec, IIFE-style Python obfuscation
    """
    payload  = get_payload(code)
    encoded  = to_b64(payload)
    v1 = rand_var(); v2 = rand_var()
    body = (
        f"import base64\n"
        f"{v1} = lambda {v2}: exec(base64.b64decode({v2}).decode())\n"
        f"{v1}(b'{encoded}')"
    )
    return body


def technique_compile(code):
    """
    exec(compile(base64.b64decode(b'...'), '<string>', 'exec'))
    Detection: compile() used with dynamic content inside exec — advanced technique
    """
    payload  = get_payload(code)
    encoded  = to_b64(payload)
    v1 = rand_var(); v2 = rand_var()
    body = (
        f"import base64\n"
        f"{v1} = base64.b64decode(b'{encoded}')\n"
        f"{v2} = compile({v1}, '<string>', 'exec')\n"
        f"exec({v2})"
    )
    return body


def technique_multi_layer(code, layers=2):
    """Chain multiple techniques in sequence."""
    pool = [
        technique_base64, technique_hex, technique_zlib,
        technique_vars, technique_unicode, technique_rot13,
    ]
    chosen = random.sample(pool, min(layers, len(pool)))
    result, log = code, []
    for i, tech in enumerate(chosen):
        result = tech(result)
        log.append(f"  Layer {i+1}: {tech.__name__.replace('technique_','')}")
    return result, log


TECHNIQUES = {
    'b64':     (technique_base64,   "base64.b64decode() + exec"),
    'hex':     (technique_hex,      "bytes.fromhex() + exec"),
    'zlib':    (technique_zlib,     "zlib.decompress(base64.b64decode()) + exec"),
    'vars':    (technique_vars,     "String split across vars + exec(''.join([...]))"),
    'unicode': (technique_unicode,  "Unicode escape string + exec"),
    'rot13':   (technique_rot13,    "codecs.decode(payload, 'rot_13') + exec"),
    'bytearray':(technique_bytearray,"bytearray([...]).decode() + exec"),
    'lambda':  (technique_lambda,   "Lambda IIFE chain + base64 + exec"),
    'compile': (technique_compile,  "compile() + exec with dynamic code object"),
    'multi':   (None,               "Multi-layer chained obfuscation"),
    'all':     (None,               "Run all techniques individually"),
}

DETECTION_NOTES = {
    'b64':      "base64.b64decode inside exec — high signal, common dropper pattern",
    'hex':      "bytes.fromhex inside exec — less common, evades base64 signatures",
    'zlib':     "zlib+base64 combo in exec — compressed payload, smallest footprint",
    'vars':     "exec(''.join([vars])) — string reassembly obfuscation",
    'unicode':  "exec with dense \\uXXXX string — evades ASCII-based pattern matching",
    'rot13':    "codecs.decode(...,'rot_13') in exec — weak but common in script kiddies",
    'bytearray':"exec(bytearray([ints]).decode()) — byte-level encoding",
    'lambda':   "Lambda chain ending in exec — functional-style obfuscation",
    'compile':  "compile() with dynamic source inside exec — advanced code object technique",
}


# ─────────────────────────────────────────────────────────────────────────────
# DEOBFUSCATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class DeobfuscationResult:
    def __init__(self):
        self.original         = ''
        self.detected_layers  = []   # [{name, confidence, evidence}]
        self.decoded_steps    = []   # [{step, method, detail, result}]
        self.final_payload    = ''
        self.iocs             = {}   # {type: [values]}
        self.mitre_techniques = []   # [{id, name, sub, relevance}]
        self.risk_score       = 0
        self.risk_label       = ''
        self.warnings         = []


def try_b64_decode(s):
    """Attempt base64 decode to UTF-8 string; return decoded or None."""
    s = s.strip().replace('\n', '').replace(' ', '')
    pad = 4 - len(s) % 4
    if pad != 4: s += '=' * pad
    try:
        d = base64.b64decode(s).decode('utf-8')
        if d.strip() and all(0x08 <= ord(c) < 0x80 or c in '\n\r\t' for c in d):
            return d
    except Exception:
        pass
    return None


def try_zlib_b64_decode(s):
    """Attempt zlib.decompress(base64.b64decode(s))."""
    s = s.strip().replace('\n', '')
    pad = 4 - len(s) % 4
    if pad != 4: s += '=' * pad
    try:
        return zlib.decompress(base64.b64decode(s)).decode('utf-8')
    except Exception:
        pass
    return None


def try_hex_decode(s):
    """Attempt bytes.fromhex decode."""
    s = s.strip().replace('\n', '').replace(' ', '')
    try:
        return bytes.fromhex(s).decode('utf-8')
    except Exception:
        pass
    return None


def try_unicode_decode(s):
    """Decode a unicode-escaped string."""
    try:
        return s.encode('utf-8').decode('unicode_escape')
    except Exception:
        pass
    return None


def try_rot13_decode(s):
    try:
        decoded = codecs.decode(s, 'rot_13')
        # Unescape Python string escape sequences that survived the rot13 pass
        # (e.g. literal \n two-chars → real newline)
        decoded = decoded.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '\r')
        return decoded
    except Exception:
        pass
    return None


def resolve_string_vars(code):
    """
    Statically resolve simple string/bytes variable assignments and substitute
    all references, including in the RHS of other assignments (to handle
    patterns like `v = zlib.decompress(b64decode(BLOB_VAR))`).

    Handles:  v = 'x'   v = "x"   v = b'x'   v = b"x"
    Returns (resolved_code, var_store_dict)
    """
    store = {}
    for m in re.finditer(
            r'^([A-Za-z_]\w*)\s*=\s*[bB]?([\'"])(.*?)\2\s*$',
            code, re.MULTILINE | re.DOTALL):
        store[m.group(1)] = m.group(3)

    if not store:
        return code, store

    lines_out = []
    for line in code.splitlines():
        stripped = line.strip()
        # Detect pure string-literal assignments (LHS = string); skip substitution in LHS
        lhs_m = re.match(r'^([A-Za-z_]\w*)\s*=\s*(.+)$', stripped)
        if lhs_m:
            lhs = lhs_m.group(1)
            rhs = lhs_m.group(2)
            # Only substitute in RHS, skip if the var on LHS is itself being defined
            # (avoid self-referential replacement)
            new_rhs = rhs
            for var, val in store.items():
                if var != lhs:  # don't replace the var being defined
                    new_rhs = re.sub(rf'\b{re.escape(var)}\b', repr(val), new_rhs)
            # Collapse string concatenations in the RHS
            def collapse(m2):
                try: return repr(eval(m2.group(0)))
                except: return m2.group(0)
            new_rhs = re.sub(r"'[^'\\]*'(?:\s*\+\s*'[^'\\]*')+", collapse, new_rhs)
            new_rhs = re.sub(r'"[^"\\]*"(?:\s*\+\s*"[^"\\]*")+', collapse, new_rhs)
            indent = line[: len(line) - len(line.lstrip())]
            lines_out.append(f"{indent}{lhs} = {new_rhs}")
        else:
            # Expression / exec / import line — substitute all known vars
            new_line = line
            for var, val in store.items():
                new_line = re.sub(rf'\b{re.escape(var)}\b', repr(val), new_line)
            def collapse2(m2):
                try: return repr(eval(m2.group(0)))
                except: return m2.group(0)
            new_line = re.sub(r"'[^'\\]*'(?:\s*\+\s*'[^'\\]*')+", collapse2, new_line)
            new_line = re.sub(r'"[^"\\]*"(?:\s*\+\s*"[^"\\]*")+', collapse2, new_line)
            lines_out.append(new_line)

    return '\n'.join(lines_out), store


def decode_bytearray_literal(s):
    """Parse bytearray([105, 109, ...]) and decode to string."""
    try:
        nums = [int(x.strip()) for x in s.split(',') if x.strip()]
        return bytearray(nums).decode('utf-8')
    except Exception:
        pass
    return None


# ── Dangerous symbol registries ───────────────────────────────────────────────

DANGEROUS_IMPORTS = {
    'os', 'subprocess', 'socket', 'ctypes', 'pty', 'shutil',
    'base64', 'zlib', 'codecs', 'marshal', 'pickle', 'shelve',
    'importlib', 'runpy', 'compileall', 'py_compile',
    'ftplib', 'smtplib', 'urllib', 'http', 'requests',
    'paramiko', 'fabric', 'pexpect', 'mimetypes',
}

DANGEROUS_CALLS = {
    'exec', 'eval', 'compile', '__import__',
    'os.system', 'os.popen', 'os.execve', 'os.execvp',
    'os.spawn', 'os.fork', 'os.getpid',
    'subprocess.call', 'subprocess.run', 'subprocess.Popen',
    'subprocess.check_output', 'subprocess.check_call',
    'socket.connect', 'socket.bind',
    'pty.spawn', 'pty.openpty',
    'ctypes.windll', 'ctypes.cdll', 'ctypes.CDLL',
    'open', 'write', 'read',
}


def extract_iocs(text):
    """Extract Python-specific and network IOCs from text."""
    iocs = {
        'ipv4': [],
        'ip_port': [],
        'url': [],
        'domain': [],
        'dangerous_imports': [],
        'dangerous_calls': [],
        'file_paths': [],
        'c2_patterns': [],
    }

    # IPv4
    for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text):
        if all(0 <= int(p) <= 255 for p in ip.split('.')) and ip not in iocs['ipv4']:
            iocs['ipv4'].append(ip)

    # IP:port in socket.connect or similar
    for m in re.finditer(r'["\'](\d{1,3}(?:\.\d{1,3}){3})["\'],?\s*(\d{2,5})', text):
        entry = f"{m.group(1)}:{m.group(2)}"
        if entry not in iocs['ip_port']: iocs['ip_port'].append(entry)

    # URLs
    for u in re.findall(r'https?://[^\s\'")\]]+', text):
        if u not in iocs['url']: iocs['url'].append(u)

    # Domains
    dom_re = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
        r'(?:com|net|org|io|gov|edu|co|sh|xyz|me|info)\b'
    )
    for d in dom_re.findall(text):
        if d not in iocs['domain']: iocs['domain'].append(d)

    # Dangerous imports
    for imp in re.finditer(r'(?:^|\b)import\s+([\w,\s]+)', text, re.MULTILINE):
        for mod in re.split(r'[,\s]+', imp.group(1)):
            mod = mod.strip()
            if mod in DANGEROUS_IMPORTS and mod not in iocs['dangerous_imports']:
                iocs['dangerous_imports'].append(mod)
    for imp in re.finditer(r'from\s+([\w.]+)\s+import', text):
        mod = imp.group(1).split('.')[0]
        if mod in DANGEROUS_IMPORTS and mod not in iocs['dangerous_imports']:
            iocs['dangerous_imports'].append(mod)

    # Dangerous calls
    for call in DANGEROUS_CALLS:
        pattern = re.escape(call) + r'\s*\('
        if re.search(pattern, text) and call not in iocs['dangerous_calls']:
            iocs['dangerous_calls'].append(call)

    # File paths
    for p in re.findall(r'["\'](?:/[\w./\-]+|[A-Za-z]:\\[\w\\.]+)["\']', text):
        p = p.strip('"\'')
        if p not in iocs['file_paths']: iocs['file_paths'].append(p)

    # C2 patterns — socket connect with IP
    for m in re.finditer(
        r'(?:connect|bind)\s*\(\s*\(?["\'](\d{1,3}(?:\.\d{1,3}){3})["\'],\s*(\d+)', text):
        entry = f"socket.connect({m.group(1)}:{m.group(2)})"
        if entry not in iocs['c2_patterns']: iocs['c2_patterns'].append(entry)

    return {k: v for k, v in iocs.items() if v}


def map_mitre(detected_layers, iocs, text):
    layer_names = set(l['name'] for l in detected_layers)
    mappings = []

    if 'base64' in layer_names or 'zlib' in layer_names:
        mappings.append({'id':'T1027.001',
            'name':'Obfuscated Files or Information: Binary Padding',
            'sub':'Base64/zlib encoded payload',
            'relevance':'Payload encoded to evade string-match detections'})
    if 'hex' in layer_names or 'bytearray' in layer_names:
        mappings.append({'id':'T1027',
            'name':'Obfuscated Files or Information',
            'sub':'Hex/byte-level encoding',
            'relevance':'Byte-level encoding obscures code content'})
    if 'unicode' in layer_names:
        mappings.append({'id':'T1027',
            'name':'Obfuscated Files or Information',
            'sub':'Unicode escape obfuscation',
            'relevance':'Unicode escapes bypass ASCII-based signature detection'})
    if 'vars' in layer_names:
        mappings.append({'id':'T1027.008',
            'name':'Obfuscated Files or Information: Stripped Payloads',
            'sub':'String splitting and dynamic assembly',
            'relevance':'Code reconstructed from fragmented string variables'})
    if 'rot13' in layer_names:
        mappings.append({'id':'T1140',
            'name':'Deobfuscate/Decode Files or Information',
            'sub':'ROT13 encoding',
            'relevance':'Weak symmetric cipher used to hide payload content'})
    if 'lambda' in layer_names or 'compile' in layer_names:
        mappings.append({'id':'T1027.010',
            'name':'Obfuscated Files or Information: Command Obfuscation',
            'sub':'Dynamic code object / lambda chain',
            'relevance':'compile()/lambda used to execute dynamically built code'})
    if re.search(r'\bexec\b|\beval\b', text):
        mappings.append({'id':'T1059.006',
            'name':'Command and Scripting Interpreter: Python',
            'sub':'exec/eval for dynamic code execution',
            'relevance':'exec/eval executes obfuscated payload at runtime'})
    if 'ip_port' in iocs or 'c2_patterns' in iocs:
        mappings.append({'id':'T1071.001',
            'name':'Application Layer Protocol: Web Protocols',
            'sub':'Socket-based C2 communication',
            'relevance':'Script establishes outbound socket connection'})
    if 'socket' in iocs.get('dangerous_imports', []):
        mappings.append({'id':'T1095',
            'name':'Non-Application Layer Protocol',
            'sub':'Raw TCP socket communication',
            'relevance':'socket module used for direct TCP/UDP C2 or exfil'})
    if 'subprocess' in iocs.get('dangerous_imports', []) or \
       any('subprocess' in c for c in iocs.get('dangerous_calls', [])):
        mappings.append({'id':'T1059',
            'name':'Command and Scripting Interpreter',
            'sub':'subprocess execution',
            'relevance':'subprocess spawns OS-level commands from Python'})
    if 'os' in iocs.get('dangerous_imports', []):
        mappings.append({'id':'T1106',
            'name':'Native API',
            'sub':'os module for system calls',
            'relevance':'os module provides direct OS API access'})
    if any('url' in str(v) or 'requests' in str(v) or 'urllib' in str(v)
           for v in iocs.values()):
        mappings.append({'id':'T1105',
            'name':'Ingress Tool Transfer',
            'sub':'HTTP/S download via requests/urllib',
            'relevance':'Script may download additional payloads'})

    seen, unique = set(), []
    for m in mappings:
        if m['id'] not in seen:
            seen.add(m['id']); unique.append(m)
    return unique


def score_risk(layers, iocs, mitre):
    score = min(len(layers) * 15, 45)
    if 'ip_port' in iocs or 'c2_patterns' in iocs: score += 25
    if 'dangerous_calls' in iocs:
        score += min(len(iocs['dangerous_calls']) * 4, 20)
    if 'dangerous_imports' in iocs:
        hi = {'socket','subprocess','ctypes','pty','os'}
        score += min(sum(3 for i in iocs['dangerous_imports'] if i in hi), 10)
    score += min(len(mitre) * 2, 10)
    score  = min(score, 100)
    label = ('CRITICAL' if score >= 75 else 'HIGH' if score >= 50
             else 'MEDIUM' if score >= 25 else 'LOW')
    return score, label


def analyze_script(code):
    """
    Multi-pass deobfuscation and analysis engine.

    Strategy: resolve all string variables first (unconditionally), then run
    every decoder on the resolved text. This handles the common case where the
    obfuscated payload is split across vars before being passed to b64decode/
    fromhex/zlib etc.  We loop up to MAX_ROUNDS times to unwrap nested layers.
    """
    MAX_ROUNDS = 6
    result          = DeobfuscationResult()
    result.original = code
    working         = code
    step_num        = 0
    seen_decoded    = set()   # avoid re-detecting same blob twice

    def _already_seen(text):
        h = hashlib.md5(text.encode()).hexdigest()
        if h in seen_decoded: return True
        seen_decoded.add(h); return False

    for _round in range(MAX_ROUNDS):
        progress = False  # did we decode anything this round?

        # ── Step A: Variable string assembly ─────────────────────────────────
        # Run unconditionally whenever there are string/bytes var assignments
        str_var_count = len(re.findall(
            r'^[A-Za-z_]\w*\s*=\s*[bB]?[\'"]', working, re.MULTILINE))
        has_exec_usage = bool(re.search(
            r'exec\s*\(|eval\s*\(', working))

        if str_var_count >= 1 and has_exec_usage:
            resolved, store = resolve_string_vars(working)
            if store and resolved != working:
                lyr_name = 'vars'
                result.detected_layers.append({'name': lyr_name, 'confidence': 'HIGH',
                    'evidence': f'{str_var_count} string assignment(s) resolved; '
                                f'{len(store)} var(s): {", ".join(list(store.keys())[:6])}'})
                step_num += 1
                result.decoded_steps.append({'step': step_num,
                    'method': 'Variable String Assembly',
                    'detail': f'Resolved {len(store)} var(s): {", ".join(list(store.keys())[:8])}',
                    'result': resolved})
                working = resolved
                progress = True

        # ── Step B: Zlib + Base64 (check before plain b64 to avoid partial match) ──
        zlib_m = re.search(
            r"zlib\.decompress\s*\(\s*base64\.b64decode\s*\(\s*b?['\"]"
            r"([A-Za-z0-9+/\n]{20,}={0,2})['\"]",
            working)
        if not zlib_m:
            # Also match pattern where var holds the b64 blob (already resolved above)
            zlib_m = re.search(
                r"zlib\.decompress\s*\(\s*base64\.b64decode\s*\(\s*b?'([A-Za-z0-9+/\n]{20,}={0,2})'",
                working)
        if zlib_m:
            raw = zlib_m.group(1).replace('\n', '').replace(' ', '')
            d = try_zlib_b64_decode(raw)
            if d and not _already_seen(d):
                result.detected_layers.append({'name': 'zlib', 'confidence': 'HIGH',
                    'evidence': f'zlib+base64 compressed payload ({len(raw)} chars) decompressed'})
                step_num += 1
                result.decoded_steps.append({'step': step_num,
                    'method': 'Zlib Decompress + Base64 Decode',
                    'detail': f'Encoded length: {len(raw)} chars → {len(d)} decoded chars',
                    'result': d})
                working = d; progress = True; continue

        # ── Step C: Base64 ────────────────────────────────────────────────────
        b64_pats = [
            re.compile(r"b64decode\s*\(\s*b?['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]"),
            re.compile(r"b64decode\s*\(\s*b?\"\"\"([A-Za-z0-9+/\n]{20,}={0,2})\"\"\""),
        ]
        matched_b64 = False
        for pat in b64_pats:
            m = pat.search(working)
            if m:
                raw = m.group(1).replace('\n', '').replace(' ', '')
                d = try_b64_decode(raw)
                if d and not _already_seen(d):
                    result.detected_layers.append({'name': 'base64', 'confidence': 'HIGH',
                        'evidence': f'base64.b64decode blob ({len(raw)} chars) decoded'})
                    step_num += 1
                    short = raw[:50] + ('…' if len(raw) > 50 else '')
                    result.decoded_steps.append({'step': step_num, 'method': 'Base64 Decode',
                        'detail': f'Encoded: {short}', 'result': d})
                    working = d; progress = True; matched_b64 = True; break
        if matched_b64: continue

        # ── Step D: Hex (bytes.fromhex) ───────────────────────────────────────
        hex_m = re.search(r"fromhex\s*\(\s*['\"]([0-9a-fA-F]{20,})['\"]", working)
        if hex_m:
            d = try_hex_decode(hex_m.group(1))
            if d and not _already_seen(d):
                result.detected_layers.append({'name': 'hex', 'confidence': 'HIGH',
                    'evidence': f'bytes.fromhex blob ({len(hex_m.group(1))//2} bytes) decoded'})
                step_num += 1
                result.decoded_steps.append({'step': step_num,
                    'method': 'Hex Decode (bytes.fromhex)',
                    'detail': f'Hex string: {len(hex_m.group(1))} chars',
                    'result': d})
                working = d; progress = True; continue

        # ── Step E: Unicode escape ─────────────────────────────────────────────
        uni_m = re.search(r'(?:exec|eval)\s*\(\s*["\']((\\u[0-9a-fA-F]{4}){10,})["\']', working)
        if uni_m:
            d = try_unicode_decode(uni_m.group(1))
            if d and not _already_seen(d):
                count = len(uni_m.group(1)) // 6
                result.detected_layers.append({'name': 'unicode', 'confidence': 'HIGH',
                    'evidence': f'{count} unicode escape sequences in exec/eval'})
                step_num += 1
                result.decoded_steps.append({'step': step_num, 'method': 'Unicode Escape Decode',
                    'detail': f'Escape count: {count}', 'result': d})
                working = d; progress = True; continue

        # ── Step F: ROT13 ─────────────────────────────────────────────────────
        rot_m = re.search(
            r"codecs\.decode\s*\(\s*(['\"])(.*?)\1\s*,\s*['\"]rot.?13['\"]",
            working, re.DOTALL)
        if rot_m:
            raw_payload = rot_m.group(2)
            # Decode Python string escape sequences before rot13
            # (repr() stores \n as \\n; we need real chars for correct decode)
            try:
                raw_payload = raw_payload.encode('raw_unicode_escape').decode('unicode_escape')
            except Exception:
                pass
            d = try_rot13_decode(raw_payload)
            if d and len(d.strip()) > 5 and not _already_seen(d):
                result.detected_layers.append({'name': 'rot13', 'confidence': 'HIGH',
                    'evidence': f"codecs.decode(...,'rot_13') — {len(rot_m.group(2))} char payload"})
                step_num += 1
                result.decoded_steps.append({'step': step_num, 'method': 'ROT13 Decode',
                    'detail': f'Encoded: {len(rot_m.group(2))} chars', 'result': d})
                working = d; progress = True; continue

        # ── Step G: exec(''.join([...])) — vars technique output ──────────────
        join_m = re.search(
            r"exec\s*\(\s*''\s*\.\s*join\s*\(\s*\[([^\]]+)\]\s*\)\s*\)", working)
        if join_m:
            try:
                parts_str = join_m.group(1)
                # Safely evaluate the list of string literals
                parts = eval(f'[{parts_str}]')
                if isinstance(parts, list) and all(isinstance(p, str) for p in parts):
                    joined = ''.join(parts)
                    if joined.strip() and not _already_seen(joined):
                        result.detected_layers.append({'name': 'vars', 'confidence': 'HIGH',
                            'evidence': f"exec(''.join([{len(parts)} parts])) — string reassembly"})
                        step_num += 1
                        result.decoded_steps.append({'step': step_num,
                            'method': "exec(''.join([...])) — String Reassembly",
                            'detail': f'{len(parts)} fragments joined',
                            'result': joined})
                        working = joined; progress = True; continue
            except Exception:
                pass

        # ── Step G: Bytearray ─────────────────────────────────────────────────
        ba_m = re.search(r"bytearray\s*\(\s*\[([0-9,\s]{10,})\]\s*\)\.decode\s*\(\s*\)",
                         working)
        if ba_m:
            d = decode_bytearray_literal(ba_m.group(1))
            if d and not _already_seen(d):
                n = ba_m.group(1).count(',') + 1
                result.detected_layers.append({'name': 'bytearray', 'confidence': 'HIGH',
                    'evidence': f'bytearray([...]).decode() — {n} elements'})
                step_num += 1
                result.decoded_steps.append({'step': step_num, 'method': 'Bytearray Decode',
                    'detail': f'Array length: {n} elements', 'result': d})
                working = d; progress = True; continue

        # ── Step H: Lambda chain ──────────────────────────────────────────────
        lam_m = re.search(r'lambda\s+\w+\s*:\s*exec\s*\(', working)
        if lam_m and 'lambda' not in [l['name'] for l in result.detected_layers]:
            result.detected_layers.append({'name': 'lambda', 'confidence': 'MEDIUM',
                'evidence': 'Lambda expression wrapping exec() detected'})
            # Find the call site: _fn(b'...') or _fn('...')
            call_m = re.search(
                r'[A-Za-z_]\w*\s*\(\s*b?[\'"]([A-Za-z0-9+/]{20,}={0,2})[\'"]',
                working)
            if call_m:
                d = try_b64_decode(call_m.group(1))
                if d and not _already_seen(d):
                    step_num += 1
                    result.decoded_steps.append({'step': step_num,
                        'method': 'Lambda Chain → Base64 Decode',
                        'detail': f'Call-site b64 payload ({len(call_m.group(1))} chars)',
                        'result': d})
                    working = d; progress = True; continue

        # ── Step I: compile() detection ───────────────────────────────────────
        comp_m = re.search(r"compile\s*\(\s*[A-Za-z_]\w*\s*,\s*['\"]<", working)
        if comp_m and 'compile' not in [l['name'] for l in result.detected_layers]:
            result.detected_layers.append({'name': 'compile', 'confidence': 'MEDIUM',
                'evidence': 'compile(dynamic_var, ...) used to build code object'})

        # No more progress — stop iterating
        if not progress:
            break

    # ── Finalize ──────────────────────────────────────────────────────────────
    # Strip exec/eval wrapper to surface the real payload
    final = working.strip()
    for _ in range(3):
        m = re.match(r'^exec\s*\((.+)\)\s*$', final, re.DOTALL)
        if m:
            inner = m.group(1).strip().strip('"\'')
            if inner and inner != final:
                final = inner
            else:
                break
        else:
            break
    result.final_payload = final

    # Build corpus from all decoded content for IOC extraction
    corpus = result.original + '\n' + result.final_payload
    for s in result.decoded_steps:
        corpus += '\n' + s.get('result', '')

    result.iocs             = extract_iocs(corpus)
    result.mitre_techniques = map_mitre(result.detected_layers, result.iocs, corpus)
    result.risk_score, result.risk_label = score_risk(
        result.detected_layers, result.iocs, result.mitre_techniques)

    if not result.detected_layers:
        result.warnings.append(
            "No known obfuscation patterns detected. "
            "Script may be plaintext or use an unsupported technique.")
    return result


# ─────────────────────────────────────────────────────────────────────────────
# ANALYSIS RENDERING
# ─────────────────────────────────────────────────────────────────────────────

RISK_C = {'CRITICAL':'\033[91m','HIGH':'\033[93m','MEDIUM':'\033[94m','LOW':'\033[92m'}
RST, BLD = '\033[0m', '\033[1m'


def render_analysis(result, use_color=True):
    R = RISK_C.get(result.risk_label,'') if use_color else ''
    B = BLD if use_color else ''; X = RST if use_color else ''
    w = 66; lines = []

    lines += [f"\n{'═'*w}", f"  {B}ANALYSIS REPORT{X}",
              f"  Timestamp : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
              f"{'═'*w}"]

    lines.append(f"\n  {B}Risk Score:{X}  {R}{result.risk_score}/100 — {result.risk_label}{X}")
    filled = int(result.risk_score / 5)
    lines.append(f"  [{R}{'█'*filled}{X}{'░'*(20-filled)}]")

    lines.append(f"\n  {B}Obfuscation Layers Detected ({len(result.detected_layers)}):{X}")
    if result.detected_layers:
        for layer in result.detected_layers:
            lines.append(f"    ◆ {layer['name'].upper():<20} [{layer['confidence']}]")
            lines.append(f"      {layer['evidence']}")
    else:
        lines.append("    None detected.")

    lines.append(f"\n  {B}Decode Steps:{X}")
    if result.decoded_steps:
        for step in result.decoded_steps:
            lines.append(f"\n    ┌─ Step {step['step']}: {B}{step['method']}{X}")
            lines.append(f"    │  Detail : {step['detail']}")
            preview = step['result'].replace('\n',' ↵ ')
            if len(preview) > 110: preview = preview[:110] + '…'
            lines.append(f"    └─ Result : {R}{preview}{X}")
    else:
        lines.append("    No decode steps performed.")

    lines.append(f"\n  {B}Recovered Payload:{X}")
    if result.final_payload:
        for line in result.final_payload.splitlines()[:20]:
            lines.append(f"    {R}{line}{X}")
        if len(result.final_payload.splitlines()) > 20:
            lines.append(f"    {R}… ({len(result.final_payload.splitlines())} lines total){X}")
    else:
        lines.append("    (unable to recover — see warnings)")

    lines.append(f"\n  {B}Extracted IOCs:{X}")
    if result.iocs:
        for k, vals in result.iocs.items():
            lines.append(f"    {k.replace('_',' ').upper()}:")
            for v in vals[:10]: lines.append(f"      • {v}")
    else:
        lines.append("    None extracted.")

    lines.append(f"\n  {B}MITRE ATT&CK Mappings ({len(result.mitre_techniques)}):{X}")
    if result.mitre_techniques:
        for m in result.mitre_techniques:
            lines += [f"    [{m['id']}] {m['name']}",
                      f"             ↳ {m['sub']}",
                      f"               {m['relevance']}"]
    else:
        lines.append("    No mappings identified.")

    if result.warnings:
        lines.append(f"\n  {B}Warnings:{X}")
        for wt in result.warnings: lines.append(f"    ⚠  {wt}")

    lines.append(f"\n{'═'*w}\n")
    return '\n'.join(lines)


def render_report_json(result):
    return {'timestamp':datetime.utcnow().isoformat()+'Z',
            'risk_score':result.risk_score,'risk_label':result.risk_label,
            'detected_layers':result.detected_layers,'decode_steps':result.decoded_steps,
            'final_payload':result.final_payload,'iocs':result.iocs,
            'mitre_techniques':result.mitre_techniques,'warnings':result.warnings,
            'original_script':result.original}


# ─────────────────────────────────────────────────────────────────────────────
# BATCH MODE
# ─────────────────────────────────────────────────────────────────────────────

SUPPORTED_EXTENSIONS = {'.py', '.pyw', '.txt', '.script', ''}


def collect_files(path, recursive=False):
    files = []
    if recursive:
        for root, _, fnames in os.walk(path):
            for fn in fnames:
                fp = os.path.join(root, fn)
                _, ext = os.path.splitext(fn)
                if ext.lower() in SUPPORTED_EXTENSIONS: files.append(fp)
    else:
        for fn in os.listdir(path):
            fp = os.path.join(path, fn)
            if os.path.isfile(fp):
                _, ext = os.path.splitext(fn)
                if ext.lower() in SUPPORTED_EXTENSIONS: files.append(fp)
    return sorted(files)


def render_batch_summary(batch_results, use_color=True):
    B = BLD if use_color else ''; X = RST if use_color else ''
    w = 74; lines = []
    lines += [f"\n{'═'*w}", f"  {B}BATCH ANALYSIS SUMMARY{X}",
              f"  Scanned : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
              f"  Files   : {len(batch_results)}", f"{'═'*w}"]

    lines.append(f"\n  {B}{'FILE':<38} {'RISK':<10} {'SCORE':>5}  {'LAYERS':<6}  PAYLOAD{X}")
    lines.append(f"  {'─'*70}")
    risk_order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'ERROR':4}
    for item in sorted(batch_results, key=lambda r: risk_order.get(r.get('risk_label','ERROR'),4)):
        fname = os.path.basename(item['file'])[:36]
        if item.get('error'):
            lines.append(f"  {fname:<38} {'ERROR':<10} {'N/A':>5}  {'N/A':<6}  {item['error'][:28]}")
            continue
        r   = item['result']
        RC  = RISK_C.get(r.risk_label,'') if use_color else ''
        payload = (r.final_payload or '(none)').replace('\n',' ')
        if len(payload) > 26: payload = payload[:26] + '…'
        lines.append(f"  {fname:<38} {RC}{r.risk_label:<10}{X} {RC}{r.risk_score:>5}{X}  "
                     f"{len(r.detected_layers):<6}  {payload}")

    # Risk distribution
    lines.append(f"\n  {B}Risk Distribution:{X}")
    counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'ERROR':0}
    for item in batch_results:
        lbl = item.get('risk_label','ERROR') if not item.get('error') else 'ERROR'
        counts[lbl] = counts.get(lbl, 0) + 1
    total = len(batch_results)
    for lbl, cnt in counts.items():
        if not cnt: continue
        RC = RISK_C.get(lbl,'') if use_color else ''
        pct = int((cnt/total)*20)
        lines.append(f"    {RC}{lbl:<10}{X}  {RC}{'█'*pct}{'░'*(20-pct)}{X}  {cnt}/{total}")

    # Aggregated IOCs
    agg = {}
    for item in batch_results:
        if item.get('error'): continue
        for k, vals in item['result'].iocs.items():
            agg.setdefault(k, set()).update(vals)
    lines.append(f"\n  {B}Aggregated IOCs (unique):{X}")
    if agg:
        for k, vals in agg.items():
            lines.append(f"    {k.replace('_',' ').upper()}:")
            for v in sorted(vals)[:12]: lines.append(f"      • {v}")
    else:
        lines.append("    None.")

    # MITRE frequency
    mc = {}
    for item in batch_results:
        if item.get('error'): continue
        for m in item['result'].mitre_techniques:
            k = f"[{m['id']}] {m['name']}"
            mc[k] = mc.get(k,0) + 1
    lines.append(f"\n  {B}MITRE ATT&CK Frequency:{X}")
    if mc:
        for tech, cnt in sorted(mc.items(), key=lambda x:-x[1]):
            lines.append(f"    {'█'*min(cnt,20):<20}  {cnt:>3}x  {tech}")
    else:
        lines.append("    None.")

    # Layer frequency
    lc = {}
    for item in batch_results:
        if item.get('error'): continue
        for l in item['result'].detected_layers:
            lc[l['name']] = lc.get(l['name'],0) + 1
    lines.append(f"\n  {B}Obfuscation Technique Frequency:{X}")
    if lc:
        for tech, cnt in sorted(lc.items(), key=lambda x:-x[1]):
            lines.append(f"    {'█'*min(cnt,20):<20}  {cnt:>3}x  {tech.upper()}")
    else:
        lines.append("    None.")

    lines.append(f"\n{'═'*w}\n")
    return '\n'.join(lines)


def render_batch_csv(batch_results):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['file','risk_label','risk_score','layers_detected','layer_names',
                     'final_payload','ipv4','ip_port','c2_patterns',
                     'dangerous_imports','dangerous_calls','mitre_ids','warnings','error'])
    for item in batch_results:
        fname = item['file']
        if item.get('error'):
            writer.writerow([fname,'ERROR',0,0,'','','','','','','','','',item['error']]); continue
        r = item['result']
        writer.writerow([fname, r.risk_label, r.risk_score, len(r.detected_layers),
            '|'.join(l['name'] for l in r.detected_layers),
            r.final_payload.replace('\n',' ')[:200],
            '|'.join(r.iocs.get('ipv4',[])),
            '|'.join(r.iocs.get('ip_port',[])),
            '|'.join(r.iocs.get('c2_patterns',[])),
            '|'.join(r.iocs.get('dangerous_imports',[])),
            '|'.join(r.iocs.get('dangerous_calls',[])),
            '|'.join(m['id'] for m in r.mitre_techniques),
            '|'.join(r.warnings), ''])
    return buf.getvalue()


def run_batch(args):
    use_color = not args.no_color
    RC = RISK_C; B = BLD if use_color else ''; X = RST if use_color else ''
    scan_dir = args.batch
    if not os.path.isdir(scan_dir):
        print(f"[!] --batch path is not a directory: {scan_dir}"); sys.exit(1)
    files = collect_files(scan_dir, recursive=args.recursive)
    if not files:
        print(f"[!] No supported Python files found in: {scan_dir}"); sys.exit(1)
    print(f"[*] Batch scan: {len(files)} file(s) in '{scan_dir}'"
          + (" (recursive)" if args.recursive else "") + "\n")
    batch_results = []; errors = 0
    for i, fpath in enumerate(files, 1):
        fname = os.path.basename(fpath)
        print(f"  [{i:>3}/{len(files)}] {fname:<42}", end='', flush=True)
        try:
            content = open(fpath,'r',errors='replace').read()
            result  = analyze_script(content)
            R2 = RC.get(result.risk_label,'') if use_color else ''
            print(f"  {R2}{result.risk_label:<10}{X}  score={result.risk_score:>3}  "
                  f"layers={len(result.detected_layers)}")
            batch_results.append({'file':fpath,'risk_label':result.risk_label,
                                   'result':result,'error':None})
            if not args.quiet: print(render_analysis(result, use_color=use_color))
            if args.report and args.output_dir:
                os.makedirs(args.output_dir, exist_ok=True)
                safe = re.sub(r'[^\w\-.]','_', fname)
                json.dump(render_report_json(result),
                          open(os.path.join(args.output_dir, f"analysis_{safe}.json"),'w'), indent=2)
        except Exception as e:
            err_msg = str(e)[:60]
            print(f"  ERROR — {err_msg}")
            batch_results.append({'file':fpath,'risk_label':'ERROR','result':None,'error':err_msg})
            errors += 1

    print(render_batch_summary(batch_results, use_color=use_color))
    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        summary_data = {'timestamp':datetime.utcnow().isoformat()+'Z',
            'scan_directory':os.path.abspath(scan_dir),'recursive':args.recursive,
            'total_files':len(files),'errors':errors,
            'results':[{'file':item['file'],'risk_label':item.get('risk_label','ERROR'),
                'risk_score':item['result'].risk_score if item['result'] else None,
                'layers':[l['name'] for l in item['result'].detected_layers] if item['result'] else [],
                'final_payload':item['result'].final_payload if item['result'] else None,
                'iocs':item['result'].iocs if item['result'] else {},
                'mitre':[m['id'] for m in item['result'].mitre_techniques] if item['result'] else [],
                'error':item.get('error')} for item in batch_results]}
        sjpath = os.path.join(args.output_dir, f"batch_summary_{ts}.json")
        json.dump(summary_data, open(sjpath,'w'), indent=2)
        scpath = os.path.join(args.output_dir, f"batch_summary_{ts}.csv")
        open(scpath,'w').write(render_batch_csv(batch_results))
        print(f"[+] Batch JSON : {sjpath}")
        print(f"[+] Batch CSV  : {scpath}\n")


# ─────────────────────────────────────────────────────────────────────────────
# DIFF MODE
# ─────────────────────────────────────────────────────────────────────────────

RISK_ORDER = {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'ERROR':0,'UNKNOWN':0}


def load_snapshot(source, recursive=False):
    if os.path.isfile(source):
        raw = json.load(open(source))
        data = {}
        for item in raw.get('results',[]):
            key = os.path.basename(item['file'])
            data[key] = {'file':item['file'],'risk_label':item.get('risk_label','UNKNOWN'),
                         'risk_score':item.get('risk_score') or 0,'layers':item.get('layers',[]),
                         'final_payload':item.get('final_payload') or '',
                         'iocs':item.get('iocs',{}),'mitre':item.get('mitre',[]),
                         'error':item.get('error')}
        return data, raw.get('timestamp','unknown'), os.path.abspath(source)
    elif os.path.isdir(source):
        files = collect_files(source, recursive=recursive)
        data  = {}
        print(f"  [scan] Analyzing {len(files)} file(s) in '{source}'...")
        for fpath in files:
            key = os.path.basename(fpath)
            try:
                content = open(fpath,'r',errors='replace').read()
                r = analyze_script(content)
                data[key] = {'file':fpath,'risk_label':r.risk_label,'risk_score':r.risk_score,
                             'layers':[l['name'] for l in r.detected_layers],
                             'final_payload':r.final_payload,'iocs':r.iocs,
                             'mitre':[m['id'] for m in r.mitre_techniques],'error':None}
            except Exception as e:
                data[key] = {'file':fpath,'risk_label':'ERROR','risk_score':0,
                             'layers':[],'final_payload':'','iocs':{},'mitre':[],'error':str(e)[:80]}
        return data, datetime.utcnow().isoformat()+'Z', os.path.abspath(source)
    else:
        print(f"[!] --diff source not found: {source}"); sys.exit(1)


def diff_snapshots(old_snap, new_snap):
    ok, nk = set(old_snap), set(new_snap)
    added, removed, common = sorted(nk-ok), sorted(ok-nk), sorted(ok&nk)
    changed, unchanged, file_details = [], [], {}
    for key in common:
        old, new = old_snap[key], new_snap[key]
        def flat(rec): return set(v for lst in rec['iocs'].values() for v in lst)
        old_iocs, new_iocs = flat(old), flat(new)
        old_layers = set(old.get('layers',[])); new_layers = set(new.get('layers',[]))
        old_mitre  = set(old.get('mitre',[]));  new_mitre  = set(new.get('mitre',[]))
        score_delta = (new['risk_score'] or 0) - (old['risk_score'] or 0)
        detail = {'old_label':old['risk_label'],'new_label':new['risk_label'],
                  'old_score':old['risk_score'],'new_score':new['risk_score'],
                  'score_delta':score_delta,'label_changed':old['risk_label']!=new['risk_label'],
                  'new_iocs':sorted(new_iocs-old_iocs),'gone_iocs':sorted(old_iocs-new_iocs),
                  'new_layers':sorted(new_layers-old_layers),'gone_layers':sorted(old_layers-new_layers),
                  'new_mitre':sorted(new_mitre-old_mitre),'gone_mitre':sorted(old_mitre-new_mitre),
                  'payload_changed':(old.get('final_payload','').strip()!=new.get('final_payload','').strip()),
                  'old_payload':old.get('final_payload',''),'new_payload':new.get('final_payload','')}
        file_details[key] = detail
        is_changed = any([detail['label_changed'], score_delta!=0, detail['new_iocs'],
                          detail['gone_iocs'], detail['new_layers'], detail['gone_layers'],
                          detail['new_mitre'], detail['gone_mitre']])
        (changed if is_changed else unchanged).append(key)

    def flat_all(snap): return set(v for rec in snap.values() for lst in rec['iocs'].values() for v in lst)
    def mitre_all(snap): return set(t for rec in snap.values() for t in rec.get('mitre',[]))
    return {'added':added,'removed':removed,'changed':changed,'unchanged':unchanged,
            'file_details':file_details,
            'net_new_iocs':sorted(flat_all(new_snap)-flat_all(old_snap)),
            'net_gone_iocs':sorted(flat_all(old_snap)-flat_all(new_snap)),
            'net_new_mitre':sorted(mitre_all(new_snap)-mitre_all(old_snap)),
            'net_gone_mitre':sorted(mitre_all(old_snap)-mitre_all(new_snap))}


def render_diff(diff, old_label, new_label, old_ts, new_ts, use_color=True):
    B = BLD if use_color else ''; X = RST if use_color else ''
    GR = '\033[92m' if use_color else ''; RD = '\033[91m' if use_color else ''
    YL = '\033[93m' if use_color else ''; w = 74; lines = []
    lines += [f"\n{'═'*w}", f"  {B}DIFF REPORT{X}",
              f"  Generated : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
              f"{'─'*w}",
              f"  {B}BASELINE (old):{X}  {old_label}",
              f"  {B}CURRENT  (new):{X}  {new_label}", f"{'═'*w}"]
    total = sum(len(diff[k]) for k in ('added','removed','changed','unchanged'))
    lines.append(f"\n  {B}Overview:{X}  {GR}+{len(diff['added'])} new{X}  "
                 f"{RD}-{len(diff['removed'])} removed{X}  {YL}~{len(diff['changed'])} changed{X}  "
                 f"{len(diff['unchanged'])} unchanged  ({total} total)")

    lines.append(f"\n  {B}{GR}NEW FILES (+{len(diff['added'])}){X}{B}:{X}")
    if diff['added']:
        for f in diff['added']: lines.append(f"    {GR}+{X} {f}")
    else: lines.append("    (none)")

    lines.append(f"\n  {B}{RD}REMOVED FILES (-{len(diff['removed'])}){X}{B}:{X}")
    if diff['removed']:
        for f in diff['removed']: lines.append(f"    {RD}-{X} {f}")
    else: lines.append("    (none)")

    lines.append(f"\n  {B}{YL}CHANGED FILES (~{len(diff['changed'])}){X}{B}:{X}")
    if diff['changed']:
        for fname in sorted(diff['changed'],
                key=lambda k: -(RISK_ORDER.get(diff['file_details'][k]['new_label'],0)
                               -RISK_ORDER.get(diff['file_details'][k]['old_label'],0))):
            d = diff['file_details'][fname]
            col = RD if d['score_delta']>0 else (GR if d['score_delta']<0 else YL)
            arrow = '▲' if d['score_delta']>0 else ('▼' if d['score_delta']<0 else '~')
            lines.append(f"\n    {col}{arrow}{X} {B}{fname}{X}")
            lines.append(f"      Risk  : {d['old_label']} → {col}{d['new_label']}{X}  "
                         f"(score {d['old_score']}→{d['new_score']}, Δ{d['score_delta']:+d})")
            for lyr in d['new_layers']:  lines.append(f"      {GR}+ Layer  : {lyr}{X}")
            for lyr in d['gone_layers']: lines.append(f"      {RD}- Layer  : {lyr}{X}")
            for ioc in d['new_iocs']:    lines.append(f"      {GR}+ IOC    : {ioc}{X}")
            for ioc in d['gone_iocs']:   lines.append(f"      {RD}- IOC    : {ioc}{X}")
            for tid in d['new_mitre']:   lines.append(f"      {GR}+ MITRE  : {tid}{X}")
            for tid in d['gone_mitre']:  lines.append(f"      {RD}- MITRE  : {tid}{X}")
            if d['payload_changed']:
                op = (d['old_payload'] or '(none)').replace('\n',' ')[:55]
                np = (d['new_payload'] or '(none)').replace('\n',' ')[:55]
                lines += [f"      {RD}- Payload: {op}{X}", f"      {GR}+ Payload: {np}{X}"]
    else: lines.append("    (none)")

    lines.append(f"\n  {B}Net New IOCs:{X}")
    if diff['net_new_iocs']:
        for ioc in diff['net_new_iocs']: lines.append(f"    {GR}+{X} {ioc}")
    else: lines.append("    (none)")

    lines.append(f"\n  {B}Net Dropped IOCs:{X}")
    if diff['net_gone_iocs']:
        for ioc in diff['net_gone_iocs']: lines.append(f"    {RD}-{X} {ioc}")
    else: lines.append("    (none)")

    lines.append(f"\n  {B}Net New MITRE Techniques:{X}")
    if diff['net_new_mitre']:
        for tid in diff['net_new_mitre']: lines.append(f"    {GR}+{X} {tid}")
    else: lines.append("    (none)")

    lines.append(f"\n  {B}Net Dropped MITRE Techniques:{X}")
    if diff['net_gone_mitre']:
        for tid in diff['net_gone_mitre']: lines.append(f"    {RD}-{X} {tid}")
    else: lines.append("    (none)")

    if diff['unchanged']:
        lines.append(f"\n  {B}Unchanged ({len(diff['unchanged'])}):{X}  "
                     + ', '.join(diff['unchanged'][:8])
                     + ('…' if len(diff['unchanged'])>8 else ''))
    lines.append(f"\n{'═'*w}\n")
    return '\n'.join(lines)


def render_diff_json(diff, old_src, new_src, old_ts, new_ts):
    return {'generated':datetime.utcnow().isoformat()+'Z',
            'baseline':{'source':old_src,'timestamp':old_ts},
            'current':{'source':new_src,'timestamp':new_ts},
            'summary':{'added':len(diff['added']),'removed':len(diff['removed']),
                       'changed':len(diff['changed']),'unchanged':len(diff['unchanged'])},
            'added_files':diff['added'],'removed_files':diff['removed'],
            'changed_files':diff['changed'],'unchanged_files':diff['unchanged'],
            'file_details':diff['file_details'],
            'net_new_iocs':diff['net_new_iocs'],'net_gone_iocs':diff['net_gone_iocs'],
            'net_new_mitre':diff['net_new_mitre'],'net_gone_mitre':diff['net_gone_mitre']}


def render_diff_csv(diff):
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(['status','file','old_risk','new_risk','score_delta',
                'new_layers','gone_layers','new_iocs','gone_iocs',
                'new_mitre','gone_mitre','payload_changed'])
    for f in diff['added']:   w.writerow(['ADDED',f,'','','','','','','','','',''])
    for f in diff['removed']: w.writerow(['REMOVED',f,'','','','','','','','','',''])
    for f in diff['changed']:
        d = diff['file_details'][f]
        w.writerow(['CHANGED',f,d['old_label'],d['new_label'],d['score_delta'],
            '|'.join(d['new_layers']),'|'.join(d['gone_layers']),
            '|'.join(d['new_iocs']),'|'.join(d['gone_iocs']),
            '|'.join(d['new_mitre']),'|'.join(d['gone_mitre']),str(d['payload_changed'])])
    for f in diff['unchanged']:
        w.writerow(['UNCHANGED',f,'','',0,'','','','','','','False'])
    return buf.getvalue()


def run_diff(args):
    use_color = not args.no_color
    old_src, new_src = args.diff
    print(f"[*] Loading baseline : {old_src}")
    old_snap, old_ts, old_abs = load_snapshot(old_src, recursive=args.recursive)
    print(f"    {len(old_snap)} file(s) loaded  (ts: {old_ts})")
    print(f"\n[*] Loading current  : {new_src}")
    new_snap, new_ts, new_abs = load_snapshot(new_src, recursive=args.recursive)
    print(f"    {len(new_snap)} file(s) loaded  (ts: {new_ts})\n")
    diff = diff_snapshots(old_snap, new_snap)
    print(render_diff(diff, old_abs, new_abs, old_ts, new_ts, use_color=use_color))
    if args.report:
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base = args.output_dir or '.'; os.makedirs(base, exist_ok=True)
        jpath = os.path.join(base, f"diff_{ts}.json")
        json.dump(render_diff_json(diff, old_abs, new_abs, old_ts, new_ts),
                  open(jpath,'w'), indent=2)
        cpath = os.path.join(base, f"diff_{ts}.csv")
        open(cpath,'w').write(render_diff_csv(diff))
        print(f"[+] Diff JSON : {jpath}\n[+] Diff CSV  : {cpath}\n")


# ─────────────────────────────────────────────────────────────────────────────
# WATCH MODE
# ─────────────────────────────────────────────────────────────────────────────

SPINNER = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']

def clear_line(): sys.stdout.write('\r\033[K'); sys.stdout.flush()
def hide_cursor(): sys.stdout.write('\033[?25l'); sys.stdout.flush()
def show_cursor(): sys.stdout.write('\033[?25h'); sys.stdout.flush()


def fingerprint_dir(directory, recursive=False):
    fp = {}
    for fpath in collect_files(directory, recursive=recursive):
        try:
            fp[os.path.basename(fpath)] = hashlib.sha256(open(fpath,'rb').read()).hexdigest()
        except Exception:
            fp[os.path.basename(fpath)] = 'ERROR'
    return fp


def fs_changed_files(old_fp, new_fp):
    ok, nk = set(old_fp), set(new_fp)
    return nk-ok, ok-nk, {k for k in ok&nk if old_fp[k] != new_fp[k]}


def fmt_alert(level, msg, use_color=True):
    if not use_color: return f"[{level}] {msg}"
    C = {'ALERT':'\033[91m','WARN':'\033[93m','INFO':'\033[96m','OK':'\033[92m'}.get(level,'')
    return f"{C}[{level}]{RST} {msg}"


def classify_diff_severity(diff, new_snap):
    for f in diff['added']:
        if new_snap.get(f,{}).get('risk_label') in ('CRITICAL','HIGH'):
            return 'ALERT', f"NEW {new_snap[f]['risk_label']} file: {f}"
    for f in diff['changed']:
        d = diff['file_details'][f]
        if (RISK_ORDER.get(d['new_label'],0) > RISK_ORDER.get(d['old_label'],0)
                and d['new_label'] in ('CRITICAL','HIGH')):
            return 'ALERT', f"ESCALATED to {d['new_label']}: {f}"
    if diff['net_new_iocs']:
        return 'WARN', f"{len(diff['net_new_iocs'])} new IOC(s): {', '.join(diff['net_new_iocs'][:3])}"
    for f in diff['changed']:
        if diff['file_details'][f]['score_delta'] > 0:
            return 'WARN', f"Score ↑ in {f}"
    if diff['removed']:  return 'INFO', f"{len(diff['removed'])} file(s) removed"
    if diff['changed']:  return 'INFO', f"{len(diff['changed'])} file(s) changed (no escalation)"
    return 'OK', "No changes detected"


class WatchSession:
    def __init__(self, watch_dir, interval, use_color):
        self.watch_dir     = watch_dir;  self.interval      = interval
        self.use_color     = use_color;  self.started_at    = datetime.utcnow()
        self.tick          = 0;          self.alerts        = 0
        self.warns         = 0;          self.total_changes = 0
        self.seen_iocs     = set();      self.event_log     = []

    def record(self, level, msg):
        self.event_log.append((datetime.utcnow().strftime('%H:%M:%S'), level, msg))
        if level == 'ALERT': self.alerts += 1
        elif level == 'WARN': self.warns  += 1

    def summary(self):
        B = BLD if self.use_color else ''; X = RST if self.use_color else ''
        elapsed = datetime.utcnow() - self.started_at
        h, rem = divmod(int(elapsed.total_seconds()),3600); m, s = divmod(rem,60)
        w = 74; lines = [f"\n{'═'*w}", f"  {B}WATCH SESSION SUMMARY{X}",
            f"  Directory  : {self.watch_dir}",
            f"  Duration   : {h:02d}:{m:02d}:{s:02d}",
            f"  Ticks      : {self.tick}  (interval: {self.interval}s)",
            f"  Alerts     : {self.alerts}", f"  Warnings   : {self.warns}",
            f"  Changes    : {self.total_changes}", f"  Unique IOCs: {len(self.seen_iocs)}"]
        if self.seen_iocs:
            lines.append("  IOCs seen  :")
            for ioc in sorted(self.seen_iocs): lines.append(f"    • {ioc}")
        if self.event_log:
            lines.append(f"\n  {B}Event Log:{X}")
            for ts, lvl, msg in self.event_log:
                lines.append(f"    [{ts}] {fmt_alert(lvl, msg, self.use_color)}")
        lines.append(f"\n{'═'*w}\n")
        return '\n'.join(lines)


def run_watch(args):
    use_color  = not args.no_color
    watch_dir  = args.watch; interval = args.interval
    recursive  = args.recursive; save_rep = args.report
    out_dir    = args.output_dir; alert_only = args.alert_only
    GR = '\033[92m' if use_color else ''; B = BLD if use_color else ''; X = RST if use_color else ''

    if not os.path.isdir(watch_dir):
        print(f"[!] --watch path is not a directory: {watch_dir}"); sys.exit(1)

    session = WatchSession(watch_dir, interval, use_color)

    def _exit(sig, frame):
        show_cursor()
        print(f"\n\n[*] Watch stopped. Session summary:")
        print(session.summary()); sys.exit(0)
    signal.signal(signal.SIGINT, _exit)

    hide_cursor()
    print(f"\n  {B}WATCH MODE{X}  →  {watch_dir}")
    print(f"  Interval   : {interval}s  |  Recursive : {recursive}")
    print(f"  Alert-only : {alert_only}  |  Reports   : {save_rep}")
    print(f"  Started    : {session.started_at.strftime('%Y-%m-%dT%H:%M:%SZ')} UTC")
    print(f"  Ctrl-C to stop and print session summary.\n")

    print(f"  {GR}[INIT]{X} Building baseline...", end='', flush=True)
    prev_fp   = fingerprint_dir(watch_dir, recursive=recursive)
    prev_snap, prev_ts, _ = load_snapshot(watch_dir, recursive=recursive)
    for rec in prev_snap.values():
        for lst in rec['iocs'].values(): session.seen_iocs.update(lst)
    clear_line()
    high = sum(1 for r in prev_snap.values() if r['risk_label'] in ('CRITICAL','HIGH'))
    print(f"  {GR}[INIT]{X} Baseline: {len(prev_snap)} file(s), "
          f"{high} high-risk, {len(session.seen_iocs)} IOC(s)")

    if save_rep and out_dir:
        os.makedirs(out_dir, exist_ok=True)
        bpath = os.path.join(out_dir, f"watch_baseline_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
        json.dump({'timestamp':prev_ts,'scan_directory':os.path.abspath(watch_dir),
                   'results':[{'file':r['file'],'risk_label':r['risk_label'],
                               'risk_score':r['risk_score'],'layers':r['layers'],
                               'final_payload':r['final_payload'],'iocs':r['iocs'],
                               'mitre':r['mitre'],'error':r['error']}
                              for r in prev_snap.values()]},
                  open(bpath,'w'), indent=2)
        print(f"  {GR}[INIT]{X} Baseline saved: {bpath}")

    spinner_i = 0
    while True:
        for remaining in range(interval, 0, -1):
            spin = SPINNER[spinner_i % len(SPINNER)]; spinner_i += 1
            elapsed_s = int((datetime.utcnow()-session.started_at).total_seconds())
            h, rem = divmod(elapsed_s,3600); m, s = divmod(rem,60)
            clear_line()
            sys.stdout.write(
                f"  {spin} Tick {session.tick+1:>4} | next in {remaining:>3}s | "
                f"uptime {h:02d}:{m:02d}:{s:02d} | "
                f"ALERT={session.alerts} WARN={session.warns} Δ={session.total_changes}")
            sys.stdout.flush(); time.sleep(1)

        clear_line(); session.tick += 1
        ts_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        ts_now = datetime.utcnow().strftime('%H:%M:%S')

        curr_fp = fingerprint_dir(watch_dir, recursive=recursive)
        added_f, removed_f, modified_f = fs_changed_files(prev_fp, curr_fp)

        if not (added_f or removed_f or modified_f):
            if not alert_only:
                print(f"  [{ts_now}] {fmt_alert('OK', 'No filesystem changes', use_color)}")
            continue

        sys.stdout.write(f"  [{ts_now}] Changes on disk — analyzing {len(curr_fp)} file(s)...")
        sys.stdout.flush()
        curr_snap, curr_ts, _ = load_snapshot(watch_dir, recursive=recursive)
        clear_line()

        diff   = diff_snapshots(prev_snap, curr_snap)
        level, reason = classify_diff_severity(diff, curr_snap)
        session.seen_iocs.update(diff['net_new_iocs'])
        session.total_changes += len(diff['added'])+len(diff['removed'])+len(diff['changed'])
        session.record(level, reason)

        n_add = len(diff['added']); n_rem = len(diff['removed']); n_chg = len(diff['changed'])
        print(f"  [{ts_now}] {fmt_alert(level, reason, use_color)}  [+{n_add} -{n_rem} ~{n_chg}]")

        if not alert_only or level in ('ALERT','WARN'):
            print(render_diff(diff, 'prev_snapshot',
                              f"{watch_dir} (tick {session.tick})",
                              prev_ts, curr_ts, use_color=use_color))

        if save_rep and out_dir:
            os.makedirs(out_dir, exist_ok=True)
            jpath = os.path.join(out_dir, f"watch_diff_{ts_str}.json")
            cpath = os.path.join(out_dir, f"watch_diff_{ts_str}.csv")
            json.dump(render_diff_json(diff,'prev_snapshot',
                                       os.path.abspath(watch_dir),prev_ts,curr_ts),
                      open(jpath,'w'), indent=2)
            open(cpath,'w').write(render_diff_csv(diff))
            print(f"  {GR}[saved]{X} {jpath}")
            print(f"  {GR}[saved]{X} {cpath}")

        prev_snap, prev_fp, prev_ts = curr_snap, curr_fp, curr_ts


# ─────────────────────────────────────────────────────────────────────────────
# OBFUSCATE RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_obfuscate(args):
    if args.seed is not None: random.seed(args.seed)
    code = open(args.file).read() if args.file else args.inline
    print(f"[*] Original ({len(code)} chars):\n")
    preview = get_payload(code)
    for line in preview.splitlines()[:5]: print(f"    {line}")
    if len(preview.splitlines()) > 5: print(f"    … ({len(preview.splitlines())} lines total)")
    print()
    results = {}

    if args.technique == 'all':
        for key, (func, desc) in {k:v for k,v in TECHNIQUES.items() if k not in ('all','multi')}.items():
            output = func(code); results[key] = output
            print_section(f"[{key.upper()}] {desc}", output, DETECTION_NOTES.get(key))
        output, log = technique_multi_layer(code, layers=args.layers)
        results['multi'] = output
        print_section(f"[MULTI] Multi-layer ({args.layers} layers)", output,
                      "Multiple stacked indicators — simulates real adversary tooling")
        print("  Layers applied:")
        for l in log: print(f"   {l}")
    elif args.technique == 'multi':
        output, log = technique_multi_layer(code, layers=args.layers)
        results['multi'] = output
        print_section(f"[MULTI] Multi-layer ({args.layers} layers)", output,
                      "Multiple stacked obfuscation indicators")
        for l in log: print(f"   {l}")
    else:
        func, desc = TECHNIQUES[args.technique]
        output = func(code); results[args.technique] = output
        print_section(f"[{args.technique.upper()}] {desc}", output, DETECTION_NOTES.get(args.technique))

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        for key, content in results.items():
            path = os.path.join(args.output_dir, f"obfuscated_{key}.py")
            open(path,'w').write(content+'\n'); print(f"\n[+] Saved: {path}")

    print(f"\n{'═'*66}\n  {len(results)} sample(s) generated.\n{'═'*66}\n")


def run_analyze(args):
    use_color = not args.no_color
    code = open(args.file).read() if args.file else args.inline
    print(f"[*] Analyzing script ({len(code)} chars)...\n")
    result = analyze_script(code)
    print(render_analysis(result, use_color=use_color))
    if args.report:
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base = args.output_dir or '.'; os.makedirs(base, exist_ok=True)
        path = os.path.join(base, f"analysis_{ts}.json")
        json.dump(render_report_json(result), open(path,'w'), indent=2)
        print(f"[+] JSON report saved: {path}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description='Python Obfuscator + Analyzer — Threat Hunt Lab',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""
        Techniques:
          b64        base64.b64decode() + exec
          hex        bytes.fromhex() + exec
          zlib       zlib.decompress(base64.b64decode()) + exec
          vars       String split across vars + exec(''.join([...]))
          unicode    Unicode escape string + exec
          rot13      codecs.decode(payload,'rot_13') + exec
          bytearray  bytearray([int,...]).decode() + exec
          lambda     Lambda IIFE chain + base64 + exec
          compile    compile() + exec with dynamic code object
          multi      Multi-layer chained (use --layers N)
          all        Run all techniques individually

        Examples:
          python3 python_obfuscator.py --inline 'import socket; ...' -t all
          python3 python_obfuscator.py -f rev.py -t zlib --seed 42
          python3 python_obfuscator.py --analyze -f obfuscated.py --report
          python3 python_obfuscator.py --batch ./samples/ --quiet --report -o ./out/
          python3 python_obfuscator.py --diff baseline.json ./new/ --report -o ./diffs/
          python3 python_obfuscator.py --watch ./samples/ --interval 15 --alert-only
        """))
    p.add_argument('--analyze',    action='store_true', help='Deobfuscate + analyze a single script')
    p.add_argument('--batch',      metavar='DIR',       help='Batch analyze all scripts in a directory')
    p.add_argument('--diff',       nargs=2, metavar=('OLD','NEW'),
                   help='Diff two snapshots (JSON files or directories)')
    p.add_argument('--watch',      metavar='DIR',       help='Continuously monitor a directory')
    p.add_argument('--interval',   type=int, default=60, help='(Watch) Seconds between scans (default: 60)')
    p.add_argument('--alert-only', action='store_true', help='(Watch) Only print ALERT/WARN events')
    p.add_argument('--recursive',  action='store_true', help='(Batch/Diff/Watch) Recurse subdirectories')
    p.add_argument('--quiet',      action='store_true', help='(Batch) Summary only')
    p.add_argument('--report',     action='store_true', help='Save JSON/CSV report(s)')
    p.add_argument('--no-color',   action='store_true', help='Disable ANSI colors')
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument('-f','--file',  help='Input Python script file')
    src.add_argument('--inline',     help='Inline Python code to process')
    p.add_argument('-t','--technique', choices=list(TECHNIQUES.keys()), default='all',
                   help='Obfuscation technique (default: all)')
    p.add_argument('--layers',  type=int, default=2, help='Layers for multi mode (default: 2)')
    p.add_argument('-o','--output-dir', help='Directory to save output files')
    p.add_argument('--list-techniques', action='store_true', help='List all techniques and exit')
    p.add_argument('--seed', type=int, help='Random seed for reproducible obfuscation')
    return p.parse_args()


def main():
    args = parse_args()
    print_banner()
    if args.list_techniques:
        print("Available Obfuscation Techniques:\n")
        for key, (_, desc) in TECHNIQUES.items(): print(f"  {key:<12} {desc}")
        print(); return
    if args.diff:   run_diff(args);    return
    if args.watch:  run_watch(args);   return
    if args.batch:  run_batch(args);   return
    if not args.file and not args.inline:
        print("[!] Provide one of: --watch <dir> | --diff OLD NEW | --batch <dir> | -f <file> | --inline '<code>'")
        sys.exit(1)
    run_analyze(args) if args.analyze else run_obfuscate(args)

if __name__ == '__main__':
    main()
