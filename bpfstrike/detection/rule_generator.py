"""
Detection Rule Generator — export YARA, Sigma, and Falco rules from
BPFStrike's forensic analysis of malicious BPF programs.

Generates deployment-ready detection rules that blue teams can immediately
use to detect the exact attack patterns BPFStrike produces:
  - YARA rules for BPF bytecode pattern matching
  - Sigma rules for SIEM log-based detection
  - Falco rules for runtime eBPF monitoring
  - Snort/Suricata signatures for network-level indicators
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from ..core.bpf_bytecode import BPFHelper, BPFProgType
from ..attacks.offensive_programs import AttackProgram, generate_all_attacks
from ..evasion.security_bypass import generate_all_evasion_attacks
from ..forensics.bpf_analyzer import (
    BPFForensicAnalyzer, ForensicReport, SUSPICIOUS_HELPER_PATTERNS,
    SUSPICIOUS_ATTACH_POINTS,
)


@dataclass
class DetectionRule:
    rule_id: str = ""
    rule_type: str = ""
    name: str = ""
    description: str = ""
    severity: str = "medium"
    mitre_technique: str = ""
    source_attack: str = ""
    rule_content: str = ""
    metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.rule_id,
            "type": self.rule_type,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
            "source_attack": self.source_attack,
            "content_length": len(self.rule_content),
        }


@dataclass
class RuleSet:
    """Collection of detection rules for a specific format."""
    format_type: str = ""
    rules: List[DetectionRule] = field(default_factory=list)
    generated_at: float = 0.0
    source_attacks: int = 0

    def to_dict(self) -> dict:
        return {
            "format": self.format_type,
            "rule_count": len(self.rules),
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(self.generated_at)),
            "source_attacks": self.source_attacks,
            "rules": [r.to_dict() for r in self.rules],
        }

    def export(self) -> str:
        """Export all rules as a single deployable file."""
        return "\n\n".join(r.rule_content for r in self.rules)


# ============================================================================
# YARA Rule Generator
# ============================================================================

def _generate_yara_rules(attacks: List[AttackProgram],
                         reports: List[ForensicReport]) -> RuleSet:
    """Generate YARA rules for BPF bytecode pattern detection."""
    rules = []

    for atk, report in zip(attacks, reports):
        prog = atk.program
        bytecode = prog.bytecode()

        # Extract signature bytes (first 32 bytes or full if shorter)
        sig_len = min(len(bytecode), 32)
        sig_hex = " ".join(f"{b:02x}" for b in bytecode[:sig_len])

        # Build helper call pattern
        helper_patterns = []
        for insn in prog.instructions:
            if (insn.opcode & 0x07) == 0x05 and (insn.opcode & 0xF0) == 0x80:
                helper_patterns.append(f"{insn.opcode:02x} ?? ?? ?? "
                                       f"{insn.imm & 0xFF:02x} "
                                       f"{(insn.imm >> 8) & 0xFF:02x} "
                                       f"{(insn.imm >> 16) & 0xFF:02x} "
                                       f"{(insn.imm >> 24) & 0xFF:02x}")

        rule_name = f"BPFStrike_{prog.name}".replace("-", "_").replace(" ", "_")
        helper_section = ""
        if helper_patterns:
            for i, hp in enumerate(helper_patterns[:5]):
                helper_section += f"        $helper_{i} = {{ {hp} }}\n"

        prog_hash = hashlib.sha256(bytecode).hexdigest()

        rule = f"""rule {rule_name} {{
    meta:
        description = "{atk.name} — {atk.description[:80]}"
        author = "BPFStrike Detection Generator"
        severity = "{report.overall_risk}"
        mitre_technique = "{atk.mitre_technique}"
        bpf_prog_type = "{prog.prog_type.name}"
        attach_point = "{prog.attach_point}"
        bytecode_hash = "{prog_hash}"
        date = "{time.strftime('%Y-%m-%d')}"

    strings:
        $bytecode_sig = {{ {sig_hex} }}
{helper_section}
    condition:
        $bytecode_sig or ({"any of ($helper_*)" if helper_patterns else "false"})
}}"""

        rules.append(DetectionRule(
            rule_id=f"YARA-BPF-{prog_hash[:8].upper()}",
            rule_type="yara",
            name=rule_name,
            description=f"Detects {atk.name} BPF bytecode pattern",
            severity=report.overall_risk,
            mitre_technique=atk.mitre_technique,
            source_attack=atk.name,
            rule_content=rule,
        ))

    # Meta-rule: detect any BPFStrike attack
    combined_names = " or ".join(
        f"BPFStrike_{a.program.name}".replace("-", "_").replace(" ", "_")
        for a in attacks
    )

    return RuleSet(
        format_type="yara",
        rules=rules,
        generated_at=time.time(),
        source_attacks=len(attacks),
    )


# ============================================================================
# Sigma Rule Generator
# ============================================================================

def _generate_sigma_rules(attacks: List[AttackProgram],
                          reports: List[ForensicReport]) -> RuleSet:
    """Generate Sigma rules for SIEM-based BPF attack detection."""
    rules = []

    # Rule 1: Suspicious BPF program load
    rules.append(DetectionRule(
        rule_id="SIGMA-BPF-001",
        rule_type="sigma",
        name="Suspicious BPF Program Load",
        description="Detects loading of BPF programs with characteristics "
                    "matching known offensive patterns",
        severity="high",
        mitre_technique="T1014",
        source_attack="generic",
        rule_content=f"""title: Suspicious BPF Program Load
id: bpfstrike-sigma-001
status: experimental
description: Detects BPF program loading events that match known offensive patterns
author: BPFStrike Detection Generator
date: {time.strftime('%Y/%m/%d')}
references:
    - https://github.com/p17433308-cmyk/BPFStrike
logsource:
    product: linux
    category: process_creation
detection:
    selection_bpf_syscall:
        Syscall: 'bpf'
        Command|contains:
            - 'BPF_PROG_LOAD'
            - 'BPF_RAW_TRACEPOINT_OPEN'
    selection_suspicious_type:
        BPFProgType|contains:
            - 'kprobe'
            - 'tracing'
            - 'raw_tracepoint'
    filter_known_tools:
        ProcessName|contains:
            - 'falco'
            - 'tetragon'
            - 'tracee'
            - 'cilium'
            - 'systemd'
    condition: (selection_bpf_syscall and selection_suspicious_type) and not filter_known_tools
level: high
tags:
    - attack.persistence
    - attack.t1014
    - attack.defense_evasion
""",
    ))

    # Rule 2: BPF program hooking sensitive functions
    sensitive_attach = list(SUSPICIOUS_ATTACH_POINTS.keys())
    attach_yaml = "\n            - ".join(f"'{a}'" for a in sensitive_attach)

    rules.append(DetectionRule(
        rule_id="SIGMA-BPF-002",
        rule_type="sigma",
        name="BPF Hook on Sensitive Kernel Function",
        description="Detects BPF programs attaching to functions commonly "
                    "used by rootkits",
        severity="critical",
        mitre_technique="T1564.001",
        source_attack="process_hider",
        rule_content=f"""title: BPF Hook on Sensitive Kernel Function
id: bpfstrike-sigma-002
status: experimental
description: Detects BPF programs attaching to sensitive kernel functions used by rootkits
author: BPFStrike Detection Generator
date: {time.strftime('%Y/%m/%d')}
references:
    - https://github.com/p17433308-cmyk/BPFStrike
logsource:
    product: linux
    service: audit
detection:
    selection:
        EventType: 'BPF'
        AttachPoint|contains:
            - {attach_yaml}
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1564.001
    - attack.credential_access
    - attack.t1056.001
""",
    ))

    # Rule 3: io_uring evasion detection
    rules.append(DetectionRule(
        rule_id="SIGMA-BPF-003",
        rule_type="sigma",
        name="io_uring Security Evasion Activity",
        description="Detects suspicious io_uring usage that may indicate "
                    "security tool evasion",
        severity="high",
        mitre_technique="T1562.001",
        source_attack="io_uring_evasion",
        rule_content=f"""title: io_uring Security Evasion Activity
id: bpfstrike-sigma-003
status: experimental
description: Detects suspicious io_uring usage patterns indicating security tool evasion
author: BPFStrike Detection Generator
date: {time.strftime('%Y/%m/%d')}
references:
    - https://github.com/p17433308-cmyk/BPFStrike
logsource:
    product: linux
    category: process_creation
detection:
    selection_uring:
        Syscall: 'io_uring_enter'
    selection_sensitive_ops:
        IoUringOp|contains:
            - 'IORING_OP_OPENAT'
            - 'IORING_OP_CONNECT'
            - 'IORING_OP_UNLINKAT'
            - 'IORING_OP_RENAMEAT'
    filter_known:
        ProcessName|contains:
            - 'nginx'
            - 'io_uring'
            - 'fio'
    condition: selection_uring and selection_sensitive_ops and not filter_known
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001
""",
    ))

    # Rule 4: BPF map manipulation
    rules.append(DetectionRule(
        rule_id="SIGMA-BPF-004",
        rule_type="sigma",
        name="BPF Map Corruption Attempt",
        description="Detects attempts to modify BPF maps owned by security tools",
        severity="critical",
        mitre_technique="T1562.001",
        source_attack="map_corruption",
        rule_content=f"""title: BPF Map Corruption Attempt
id: bpfstrike-sigma-004
status: experimental
description: Detects modification of BPF maps belonging to security monitoring tools
author: BPFStrike Detection Generator
date: {time.strftime('%Y/%m/%d')}
references:
    - https://github.com/p17433308-cmyk/BPFStrike
logsource:
    product: linux
    service: audit
detection:
    selection:
        Syscall: 'bpf'
        Command: 'BPF_MAP_UPDATE_ELEM'
    selection_security_maps:
        MapName|contains:
            - 'syscall_table'
            - 'proc_table'
            - 'tg_conf_map'
            - 'tg_execve_map'
            - 'config_map'
            - 'proc_info_map'
    condition: selection and selection_security_maps
level: critical
tags:
    - attack.defense_evasion
    - attack.t1562.001
""",
    ))

    # Rule 5: Credential harvesting via BPF
    rules.append(DetectionRule(
        rule_id="SIGMA-BPF-005",
        rule_type="sigma",
        name="BPF Credential Harvesting",
        description="Detects BPF programs hooking authentication functions",
        severity="critical",
        mitre_technique="T1056.001",
        source_attack="credential_harvester",
        rule_content=f"""title: BPF Credential Harvesting
id: bpfstrike-sigma-005
status: experimental
description: Detects BPF programs hooking PAM or SSH authentication functions
author: BPFStrike Detection Generator
date: {time.strftime('%Y/%m/%d')}
references:
    - https://github.com/p17433308-cmyk/BPFStrike
logsource:
    product: linux
    service: audit
detection:
    selection:
        EventType: 'BPF'
        AttachPoint|contains:
            - 'pam_sm_authenticate'
            - 'auth_password'
            - 'pam_unix'
    selection_helpers:
        BPFHelpers|contains:
            - 'probe_read'
            - 'ringbuf_reserve'
            - 'perf_event_output'
    condition: selection or (selection and selection_helpers)
level: critical
tags:
    - attack.credential_access
    - attack.t1056.001
""",
    ))

    return RuleSet(
        format_type="sigma",
        rules=rules,
        generated_at=time.time(),
        source_attacks=len(attacks),
    )


# ============================================================================
# Falco Rule Generator
# ============================================================================

def _generate_falco_rules(attacks: List[AttackProgram],
                          reports: List[ForensicReport]) -> RuleSet:
    """Generate Falco rules for runtime eBPF monitoring."""
    rules = []

    # Rule 1: Suspicious BPF program loaded
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-001",
        rule_type="falco",
        name="Suspicious BPF Program Loaded",
        description="Detects loading of BPF programs from non-standard processes",
        severity="warning",
        mitre_technique="T1014",
        source_attack="generic",
        rule_content=f"""- rule: Suspicious BPF Program Loaded
  desc: >
    Detects BPF program loading from processes not in the known security
    tool allowlist. BPF programs can hook kernel functions, intercept
    syscalls, and modify network traffic at the driver level.
  condition: >
    evt.type = bpf and
    evt.arg.cmd = BPF_PROG_LOAD and
    not proc.name in (falco, tetragon, cilium-agent, tracee, systemd,
                      bpftrace, bpftool, tc, ip)
  output: >
    Suspicious BPF program loaded (user=%user.name process=%proc.name
    pid=%proc.pid prog_type=%evt.arg.prog_type
    attach=%evt.arg.attach_type parent=%proc.pname)
  priority: WARNING
  tags: [bpf, rootkit, T1014]
""",
    ))

    # Rule 2: BPF program hooking getdents
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-002",
        rule_type="falco",
        name="BPF Process Hiding Hook Detected",
        description="Detects BPF programs attaching to getdents64 — "
                    "primary process hiding technique",
        severity="critical",
        mitre_technique="T1564.001",
        source_attack="process_hider",
        rule_content=f"""- rule: BPF Process Hiding Hook Detected
  desc: >
    A BPF program was attached to getdents64 or getdents, which is the
    primary syscall used for directory listing. Hooking this syscall is
    the standard technique for hiding processes and files from
    enumeration tools (ps, ls, find, top).
  condition: >
    evt.type = bpf and
    (evt.arg.attach_point contains "getdents64" or
     evt.arg.attach_point contains "getdents" or
     evt.arg.attach_point contains "iterate_dir")
  output: >
    BPF process/file hiding hook detected (user=%user.name
    process=%proc.name pid=%proc.pid
    attach=%evt.arg.attach_point)
  priority: CRITICAL
  tags: [bpf, rootkit, process_hiding, T1564.001]
""",
    ))

    # Rule 3: BPF credential harvesting
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-003",
        rule_type="falco",
        name="BPF Credential Harvesting Detected",
        description="Detects BPF programs hooking authentication functions",
        severity="critical",
        mitre_technique="T1056.001",
        source_attack="credential_harvester",
        rule_content=f"""- rule: BPF Credential Harvesting Detected
  desc: >
    A BPF program was attached to PAM or SSH authentication functions.
    This is a credential harvesting technique that captures usernames
    and password verification events at the kernel level.
  condition: >
    evt.type = bpf and
    (evt.arg.attach_point contains "pam_sm_authenticate" or
     evt.arg.attach_point contains "auth_password" or
     evt.arg.attach_point contains "pam_unix")
  output: >
    BPF credential harvesting hook detected (user=%user.name
    process=%proc.name pid=%proc.pid
    attach=%evt.arg.attach_point)
  priority: CRITICAL
  tags: [bpf, credential_theft, T1056.001]
""",
    ))

    # Rule 4: BPF override_return usage
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-004",
        rule_type="falco",
        name="BPF Override Return Detected",
        description="Detects BPF programs using bpf_override_return — "
                    "the core rootkit mechanism",
        severity="critical",
        mitre_technique="T1014",
        source_attack="process_hider",
        rule_content=f"""- rule: BPF Override Return Detected
  desc: >
    A BPF program is using bpf_override_return, which modifies syscall
    return values. This is the primary mechanism for BPF rootkits to
    hide processes, files, and network connections. Legitimate use is
    extremely rare outside of error injection testing.
  condition: >
    evt.type = bpf and
    evt.arg.helpers contains "override_return"
  output: >
    BPF override_return usage detected — possible rootkit
    (user=%user.name process=%proc.name pid=%proc.pid
    prog_type=%evt.arg.prog_type)
  priority: CRITICAL
  tags: [bpf, rootkit, override_return, T1014]
""",
    ))

    # Rule 5: XDP program loaded
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-005",
        rule_type="falco",
        name="XDP Program Loaded Outside Network Stack",
        description="Detects XDP programs loaded by non-network processes",
        severity="warning",
        mitre_technique="T1557",
        source_attack="xdp_interceptor",
        rule_content=f"""- rule: XDP Program Loaded Outside Network Stack
  desc: >
    An XDP (eXpress Data Path) program was loaded by a process that is
    not part of the standard network stack. XDP operates at the NIC
    driver level and can intercept, modify, or drop packets before they
    reach the kernel network stack, making it invisible to tcpdump,
    iptables, and standard network monitoring.
  condition: >
    evt.type = bpf and
    evt.arg.prog_type = XDP and
    not proc.name in (tc, ip, cilium-agent, xdp-loader, bpftool)
  output: >
    XDP program loaded by non-network process (user=%user.name
    process=%proc.name pid=%proc.pid interface=%evt.arg.ifname)
  priority: WARNING
  tags: [bpf, network, xdp, T1557]
""",
    ))

    # Rule 6: BPF self-hiding attempt
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-006",
        rule_type="falco",
        name="BPF Self-Hiding Program Detected",
        description="Detects BPF programs hooking BPF enumeration functions",
        severity="critical",
        mitre_technique="T1014",
        source_attack="bpf_self_hider",
        rule_content=f"""- rule: BPF Self-Hiding Program Detected
  desc: >
    A BPF program was attached to BPF enumeration or information
    retrieval functions (bpf_prog_get_info_by_fd, bpf iterator).
    This technique hides BPF programs from bpftool and /proc
    enumeration, making rootkit components invisible.
  condition: >
    evt.type = bpf and
    (evt.arg.attach_point contains "bpf_prog_get_info" or
     evt.arg.prog_type = "bpf_iter" or
     evt.arg.attach_point contains "bpf_prog_iter")
  output: >
    BPF self-hiding attempt detected (user=%user.name
    process=%proc.name pid=%proc.pid
    attach=%evt.arg.attach_point)
  priority: CRITICAL
  tags: [bpf, rootkit, self_hiding, T1014]
""",
    ))

    # Rule 7: io_uring evasion
    rules.append(DetectionRule(
        rule_id="FALCO-BPF-007",
        rule_type="falco",
        name="Suspicious io_uring Activity",
        description="Detects io_uring operations that bypass BPF monitoring",
        severity="warning",
        mitre_technique="T1562.001",
        source_attack="io_uring_evasion",
        rule_content=f"""- rule: Suspicious io_uring Activity
  desc: >
    Detects processes using io_uring for operations that typically go
    through monitored syscalls. io_uring executes in kernel worker
    threads and bypasses all tracepoint-based and most kprobe-based
    security monitoring, including Falco's own syscall hooks.
  condition: >
    evt.type = io_uring_enter and
    evt.arg.opcode in (IORING_OP_OPENAT, IORING_OP_CONNECT,
                       IORING_OP_UNLINKAT, IORING_OP_RENAMEAT) and
    not proc.name in (nginx, io_uring_test, fio)
  output: >
    Suspicious io_uring operation (user=%user.name process=%proc.name
    pid=%proc.pid opcode=%evt.arg.opcode)
  priority: WARNING
  tags: [io_uring, evasion, T1562.001]
""",
    ))

    return RuleSet(
        format_type="falco",
        rules=rules,
        generated_at=time.time(),
        source_attacks=len(attacks),
    )


# ============================================================================
# Snort/Suricata Rule Generator
# ============================================================================

def _generate_network_rules(attacks: List[AttackProgram]) -> RuleSet:
    """Generate Snort/Suricata rules for network-level indicators."""
    rules = []

    rules.append(DetectionRule(
        rule_id="SNORT-BPF-001",
        rule_type="snort",
        name="BPF Rootkit C2 Beacon Pattern",
        description="Detects network patterns associated with BPF rootkit "
                    "command-and-control communication",
        severity="high",
        mitre_technique="T1071",
        source_attack="net_interceptor",
        rule_content=f"""# BPFStrike Network Detection Rules
# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}

# Rule 1: Detect potential BPF rootkit C2 beacon
alert tcp any any -> any any (msg:"BPFStrike - Potential BPF rootkit C2 beacon"; \\
    flow:established; \\
    content:"|de ad be ef|"; depth:4; \\
    threshold:type both, track by_src, count 5, seconds 60; \\
    classtype:trojan-activity; \\
    sid:3000001; rev:1;)

# Rule 2: Detect BPF data exfiltration pattern
alert tcp any any -> any any (msg:"BPFStrike - BPF data exfiltration pattern"; \\
    flow:established,to_server; \\
    dsize:>1000; \\
    content:"|00 00 00 00|"; offset:0; depth:4; \\
    pcre:"/^\\x00{{4}}[\\x00-\\xff]{{4,}}$/"; \\
    threshold:type both, track by_src, count 10, seconds 30; \\
    classtype:trojan-activity; \\
    sid:3000002; rev:1;)

# Rule 3: Detect XDP-rewritten packet anomalies
alert tcp any any -> any any (msg:"BPFStrike - XDP packet rewrite anomaly"; \\
    flow:established; \\
    flags:S; \\
    ttl:<5; \\
    classtype:misc-attack; \\
    sid:3000003; rev:1;)
""",
    ))

    return RuleSet(
        format_type="snort",
        rules=rules,
        generated_at=time.time(),
        source_attacks=len(attacks),
    )


# ============================================================================
# Main Detection Rule Generator
# ============================================================================

class DetectionRuleGenerator:
    """Generate detection rules from BPFStrike attack analysis."""

    FORMATS = ["yara", "sigma", "falco", "snort"]

    def __init__(self):
        self.rulesets: Dict[str, RuleSet] = {}

    def generate_all(self) -> Dict[str, RuleSet]:
        """Generate all detection rule formats."""
        attacks = generate_all_attacks() + generate_all_evasion_attacks()
        analyzer = BPFForensicAnalyzer()
        reports = analyzer.batch_analyze([a.program for a in attacks])

        self.rulesets["yara"] = _generate_yara_rules(attacks, reports)
        self.rulesets["sigma"] = _generate_sigma_rules(attacks, reports)
        self.rulesets["falco"] = _generate_falco_rules(attacks, reports)
        self.rulesets["snort"] = _generate_network_rules(attacks)

        return self.rulesets

    def generate_format(self, fmt: str) -> Optional[RuleSet]:
        """Generate rules for a specific format."""
        attacks = generate_all_attacks() + generate_all_evasion_attacks()
        analyzer = BPFForensicAnalyzer()
        reports = analyzer.batch_analyze([a.program for a in attacks])

        generators = {
            "yara": lambda: _generate_yara_rules(attacks, reports),
            "sigma": lambda: _generate_sigma_rules(attacks, reports),
            "falco": lambda: _generate_falco_rules(attacks, reports),
            "snort": lambda: _generate_network_rules(attacks),
        }

        if fmt not in generators:
            return None

        ruleset = generators[fmt]()
        self.rulesets[fmt] = ruleset
        return ruleset

    def total_rules(self) -> int:
        return sum(len(rs.rules) for rs in self.rulesets.values())

    def summary(self) -> dict:
        return {
            "formats": list(self.rulesets.keys()),
            "total_rules": self.total_rules(),
            "per_format": {
                fmt: len(rs.rules) for fmt, rs in self.rulesets.items()
            },
        }
