# 🐢 CozyTurtle

> **A repository of threat-hunting lab tools — script obfuscators paired with their own deobfuscation/analysis engines, built for detection-rule development and analyst training.**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](#license)
[![Python: 3.6+](https://img.shields.io/badge/Python-3.6+-green.svg)](#requirements)
[![Shell: bash 5.2](https://img.shields.io/badge/Shell-bash%205.2-blue.svg)](#requirements)
[![MITRE ATT&CK: Mapped](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-red.svg)](#mitre-attck-coverage)
[![Use: Authorized Lab Only](https://img.shields.io/badge/Use-Authorized%20Lab%20Only-orange.svg)](#-disclaimer)

---

## Overview

CozyTurtle is a collection of **threat-hunting lab tools** for generating, analyzing, and detecting obfuscated scripts. The two centerpieces are a **Python script obfuscator/analyzer** and a **bash script obfuscator/analyzer** — each tool can both *produce* obfuscated samples and *reverse* them, surfacing the hidden payload, extracting indicators of compromise, and mapping the behavior to MITRE ATT&CK.

The intent is detection engineering and analyst training. Rather than hunting for real malware to study, an instructor or detection engineer can generate a controlled corpus of obfuscated samples using known techniques, then run the analysis engine to validate that detections fire, practice manual deobfuscation, and build a labeled dataset for writing and tuning rules.

A small set of sample payload artifacts (a reverse-shell script, a shell-upgrade helper, and a systemd service unit) are included as realistic, benign-by-design inputs to obfuscate, analyze, and detect.

> **Built and used in isolated lab environments only.** See the [disclaimer](#-disclaimer).

---

## What's Included

| File | Type | Purpose |
|---|---|---|
| `python_obfuscator.py` | Python | Python script obfuscator **+** deobfuscation/analysis engine |
| `bash_obfuscator.py` | Python | Bash script obfuscator (original) |
| `bash_obfuscator_v3.py` | Python | Bash obfuscator/analyzer, expanded — adds batch, diff, and watch modes |
| `revShell.sh` | Shell | Sample reverse-shell payload used as a test input |
| `ShellUpgrade` | Shell | Shell/TTY upgrade helper used as a test input |
| `sys-update.service` | systemd unit | Sample service unit — a persistence artifact for detection practice |
| `LICENSE` | — | MIT License |

---

## Tools

### `python_obfuscator.py` — Python Obfuscator + Analyzer

A dual-purpose tool: it generates obfuscated Python samples and reverses/analyzes them. Pure Python standard library, targeting Python 3.6+.

**Obfuscation techniques** (each documented with the detection signature it produces):

| Technique | Method | Hunt signature |
|---|---|---|
| `b64` | `base64.b64decode()` + `exec` | base64 decode inside exec/eval |
| `hex` | `bytes.fromhex()` + `exec` | hex blob inside exec, evades base64 sigs |
| `zlib` | `zlib.decompress(base64.b64decode())` + `exec` | compress+encode combo, smallest footprint |
| `vars` | string split across variables, `exec(''.join([...]))` | many short string vars reassembled |
| `unicode` | dense `\uXXXX` escape string + `exec` | unicode escapes bypass ASCII matching |
| `rot13` | `codecs.decode(..., 'rot_13')` + `exec` | weak symmetric encoding in exec |
| `bytearray` | `exec(bytearray([...]).decode())` | byte-level integer list |
| `lambda` | lambda IIFE chain wrapping `exec` | functional-style obfuscation |
| `compile` | `compile()` dynamic code object + `exec` | advanced dynamic execution |
| `multi` | chains several techniques in sequence | stacked indicators, mimics real tooling |

**Analysis engine** performs multi-pass deobfuscation (up to several unwrap rounds), resolving variable assembly, decoding each layer, and then:

- **Recovers the final payload** by unwinding nested encodings and stripping the `exec`/`eval` wrapper
- **Extracts IOCs** — IPv4, IP:port, URLs, domains, dangerous imports (`os`, `subprocess`, `socket`, `ctypes`, `pty`, …), dangerous calls, file paths, and socket-based C2 patterns
- **Maps to MITRE ATT&CK** based on the detected layers and behavior (see [coverage](#mitre-attck-coverage))
- **Scores risk** 0–100 with a CRITICAL/HIGH/MEDIUM/LOW label, weighting obfuscation depth, C2 indicators, and dangerous calls/imports
- **Renders** a color terminal report or a JSON report for tooling

**Modes:** single-file/inline obfuscation, single-file/inline analysis, **batch** directory scanning (recursive), **diff** between two snapshots, and **watch** for continuous monitoring of a directory.

### `bash_obfuscator_v3.py` — Bash Obfuscator + Analyzer

The bash counterpart, targeting GNU bash 5.2. Same generate-and-reverse design, with bash-specific techniques:

| Technique | Method | Hunt signature |
|---|---|---|
| `b64` | base64 encode + `eval`/`base64 -d` | `base64 -d \| bash` or eval+decode |
| `hex` | `printf '\xNN'` + `eval` | printf hex sequences + eval |
| `vars` | variable split + assembly | many short random vars building a command |
| `ansi` | ANSI-C quoting `$'\xNN'` on the command word | `$'\x..'` in command position |
| `ifs` | `IFS` manipulation + `read` split | IFS reassignment before execution |
| `here` | heredoc piped to bash | heredoc with base64 content to `bash` |
| `glob` | glob/wildcard path expansion (e.g. `/???/b?sh`) | anomalous wildcard process paths |
| `multi` | chained layers | stacked indicators |

Its analysis engine resolves variables, decodes ANSI-C/hex/base64/heredoc/IFS layers, flags glob paths that require runtime resolution, and extracts bash-centric IOCs — `/dev/tcp` and `/dev/udp` redirects, `bash -i`/`sh -i` interactive shells, `nc`/`ncat`/`socat`, `curl|bash` / `wget|bash` patterns, inline interpreter execution (`python -c`, `perl -e`, `php -r`), persistence/detach commands (`nohup`, `disown`), and SSH remote-forward usage. Output supports terminal, JSON, and **CSV** (for SIEM/spreadsheet ingestion), plus the batch/diff/watch workflow for tracking how a sample set changes over time.

> `bash_obfuscator.py` is the original single-file version; `bash_obfuscator_v3.py` is the expanded build with batch, diff, and watch added.

---

## Usage

### Python tool

```bash
# Obfuscate
python3 python_obfuscator.py -f script.py -t all
python3 python_obfuscator.py -f script.py -t b64
python3 python_obfuscator.py --inline 'import socket; ...' -t all
python3 python_obfuscator.py -f script.py -t multi --layers 3
python3 python_obfuscator.py -f script.py -t all -o ./samples/

# Analyze / deobfuscate
python3 python_obfuscator.py --analyze -f obfuscated.py
python3 python_obfuscator.py --analyze -f obfuscated.py --report -o ./reports/

# Batch / diff / watch
python3 python_obfuscator.py --batch ./samples/ --recursive --report -o ./reports/
python3 python_obfuscator.py --diff baseline.json ./new_samples/
python3 python_obfuscator.py --watch ./samples/ --interval 30

# Reference
python3 python_obfuscator.py --list-techniques
```

### Bash tool

```bash
# Obfuscate
python3 bash_obfuscator_v3.py -f script.sh -t all
python3 bash_obfuscator_v3.py --inline '<your test command>' -t b64
python3 bash_obfuscator_v3.py -f script.sh -t multi --layers 3

# Analyze / deobfuscate
python3 bash_obfuscator_v3.py --analyze -f obfuscated.sh --report
python3 bash_obfuscator_v3.py --batch ./samples/ --recursive --report -o ./reports/
python3 bash_obfuscator_v3.py --watch ./samples/ --interval 30 --alert-only

# Reference
python3 bash_obfuscator_v3.py --list-techniques
```

> Both tools accept `--seed` for reproducible sample generation and `--no-color` for clean piping/logging.

---

## Requirements

- **Python 3.6+** (standard library only — no pip packages required)
- **GNU bash 5.2.x** for running/validating the bash samples
- A Linux analysis host; an isolated VM or lab segment is strongly recommended

---

## Suggested Lab Workflow

1. **Generate** a labeled corpus of obfuscated samples across all techniques and a few `multi --layers` depths (`--seed` for reproducibility).
2. **Detect** — run your SIEM/EDR rules, YARA, or `grep`-based signatures against the corpus and confirm they fire on each technique's signature.
3. **Analyze** — run the built-in analyzer to recover payloads, extract IOCs, and produce ATT&CK-mapped JSON/CSV for each sample.
4. **Tune** — use the false-negative gaps to refine detections; re-run and compare with `--diff` to measure improvement.
5. **Monitor** — use `--watch` on a sample drop folder to demonstrate continuous detection in a classroom setting.

---

## MITRE ATT&CK Coverage

The analyzers map detected behavior to ATT&CK techniques, including:

| Technique | ID |
|---|---|
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) |
| — Binary Padding (base64/zlib encoding) | [T1027.001](https://attack.mitre.org/techniques/T1027/001/) |
| — Stripped Payloads (string split/assembly) | [T1027.008](https://attack.mitre.org/techniques/T1027/008/) |
| — Command Obfuscation (eval / dynamic code) | [T1027.010](https://attack.mitre.org/techniques/T1027/010/) |
| Deobfuscate/Decode Files or Information (ROT13) | [T1140](https://attack.mitre.org/techniques/T1140/) |
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) |
| — Unix Shell (`/dev/tcp`, `bash -i`) | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| — Python (`exec`/`eval`) | [T1059.006](https://attack.mitre.org/techniques/T1059/006/) |
| Application Layer Protocol: Web Protocols (C2) | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Non-Application Layer Protocol (raw TCP) | [T1095](https://attack.mitre.org/techniques/T1095/) |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) |
| Native API (`os` module) | [T1106](https://attack.mitre.org/techniques/T1106/) |

The sample `sys-update.service` unit is included as a **Create or Modify System Process: systemd Service** ([T1543.002](https://attack.mitre.org/techniques/T1543/002/)) persistence artifact for hunting and detection practice.

---

## ⚠ Disclaimer

These tools generate and analyze **obfuscated code and sample offensive payloads** for **authorized cybersecurity education, detection engineering, and threat-hunting training** in **isolated lab environments only**.

**DO NOT:**

- Use against systems or networks without explicit written authorization
- Deploy on production systems or expose to untrusted networks
- Repurpose the obfuscation output to evade detection on systems you do not own or are not authorized to test
- Redistribute as weaponized tooling

The obfuscation techniques are intentionally paired with their detection signatures and a working analysis engine — the goal is to teach defenders how these techniques look and how to reverse them, not to provide an evasion toolkit. Use responsibly and legally.

---

## License

MIT License — see [LICENSE](LICENSE).

[jhenry.io](https://jhenry.io)
