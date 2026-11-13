# Contributing to BPFStrike

Thank you for your interest in eBPF security research.

## Scope

BPFStrike is an **eBPF offensive security framework** for authorized testing. Contributions must:

- Target only Linux kernel eBPF subsystems
- Include detection/mitigation guidance for every offensive technique
- Work within the eBPF verifier's constraints (no kernel exploits)

## How to Contribute

### Bug Reports
Open an issue with: kernel version, BPF subsystem details, full traceback, and the command you ran.

### New Modules
Additional eBPF offensive techniques with:
- A module in the appropriate category (persistence, evasion, exfiltration, etc.)
- Corresponding detection rules or signatures
- Documentation of the technique and its limitations
- Test coverage

### Detection Rules
Defensive signatures (Sigma, YARA, or custom) that detect BPFStrike techniques.

### Kernel Version Support
Testing and compatibility fixes for additional kernel versions.

## Development Setup

```bash
git clone https://github.com/p17433308-cmyk/BPFStrike.git
cd BPFStrike
pip install -e .
pytest tests/
```

## Requirements

- Linux kernel 5.8+ (for BPF ring buffer support)
- Root/CAP_BPF for loading BPF programs
- Python 3.9+

## Code Style

- Python 3.9+, type hints encouraged
- Tests for every new module
- Detection guidance is mandatory for offensive techniques

## Responsible Use

All contributions must be designed for authorized security testing. Include clear warnings and scope limitations in any new offensive module.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
