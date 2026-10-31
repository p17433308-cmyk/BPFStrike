# BPFStrike — eBPF Offensive Security Framework

BPFStrike is a comprehensive eBPF offensive security toolkit that generates real BPF bytecode for attack simulation, security tool evasion, kernel reconnaissance, forensic analysis, and verifier bypass research.

## Features

- **8 Offensive BPF Programs** — Syscall hooking, process hiding, XDP interception, credential harvesting, container escape, file hiding, keylogging, BPF self-hiding
- **Security Tool Evasion** — Bypass Falco, Tetragon, Tracee via io_uring and map corruption
- **BPF Reconnaissance** — Enumerate kernel BPF capabilities, loaded programs, maps, and security tools
- **Forensic Analysis** — Detect malicious BPF programs via bytecode pattern analysis with MITRE ATT&CK mapping
- **Verifier Bypass Patterns** — CVE-based bypass demonstrations and complexity bombs
- **Real Bytecode** — Every program generates valid eBPF instructions (not simulation)
- **ELF Generation** — Produce loadable `.o` files for bpftool/libbpf

## Installation

```bash
pip install -e .
```

## Usage

```bash
# Full demonstration
bpfstrike demo

# Generate all offensive programs
bpfstrike generate

# Generate specific attack with disassembly
bpfstrike generate syscall_hook --disasm

# Generate and save ELF objects
bpfstrike generate -o ./output/

# BPF subsystem reconnaissance
bpfstrike recon

# Analyze bpftool output
bpfstrike recon --bpftool-progs progs.json --bpftool-maps maps.json

# Forensic analysis of all attack patterns
bpfstrike forensics

# Analyze raw bytecode
bpfstrike forensics --bytecode-file suspicious.bin -o report.json

# Verifier bypass patterns
bpfstrike verifier

# List known verifier CVEs
bpfstrike verifier --list-cves
```

## Architecture

```
bpfstrike/
├── core/
│   ├── bpf_bytecode.py    # eBPF ISA: opcodes, registers, instruction builders
│   └── elf_generator.py   # Minimal ELF .o generation for BPF programs
├── attacks/
│   └── offensive_programs.py  # 8 attack program generators
├── evasion/
│   └── security_bypass.py     # Falco/Tetragon/Tracee evasion
├── recon/
│   └── bpf_scanner.py         # BPF subsystem enumeration
├── forensics/
│   └── bpf_analyzer.py        # Malicious BPF detection
├── verifier/
│   └── bypass_patterns.py     # Verifier CVEs and bypass patterns
└── cli.py                     # Command-line interface
```

## Attack Programs

| Attack | Type | Attach Point | MITRE |
|--------|------|-------------|-------|
| Syscall Hook | kprobe | __x64_sys_read | T1059 |
| Process Hider | kprobe | __x64_sys_getdents64 | T1564.001 |
| XDP Interceptor | xdp | eth0 | T1557 |
| Credential Harvester | kprobe | pam_sm_authenticate | T1056.001 |
| Container Escape | cgroup_skb | docker cgroup | T1611 |
| File Hider | tracepoint | sys_exit_getdents64 | T1564.001 |
| Keylogger | tracepoint | sys_enter_write | T1056.001 |
| BPF Self-Hider | tracing | bpf_prog iterator | T1014 |
| io_uring Evasion | kprobe | io_submit_sqes | T1562.001 |
| Map Corruptor | kprobe | __x64_sys_bpf | T1562.001 |

## Verifier CVEs

- CVE-2021-3490 — ALU32 bounds tracking confusion
- CVE-2021-31440 — 32-bit register spill bypass
- CVE-2022-23222 — Pointer arithmetic confusion
- CVE-2023-2163 — Dead code pruning bypass
- CVE-2023-39191 — Precision tracking overflow
- CVE-2024-2193 — Spectre-BPF type confusion

## Author

Dr. Sapna V M

## License

MIT
