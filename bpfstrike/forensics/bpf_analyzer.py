"""
BPF forensic analysis — detect malicious BPF programs by analyzing bytecode
patterns, helper usage, and behavioral indicators.

This module performs static analysis of BPF bytecode to identify:
  - Rootkit patterns (getdents hooking, process hiding, file hiding)
  - Credential theft (auth function hooking, key material access)
  - Network interception (XDP modification, packet rewriting)
  - Persistence mechanisms (cgroup attachment, iterator abuse)
  - Security tool evasion (override_return, map corruption)
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

from ..core.bpf_bytecode import (
    BPFInsn, BPFProgram, BPFHelper, BPFClass, BPFJmp, BPFProgType,
)


@dataclass
class ForensicIndicator:
    indicator_type: str = ""
    severity: str = "medium"
    confidence: float = 0.5
    description: str = ""
    evidence: str = ""
    instruction_offset: int = -1
    mitre_technique: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.indicator_type,
            "severity": self.severity,
            "confidence": f"{self.confidence:.0%}",
            "description": self.description,
            "evidence": self.evidence,
            "instruction_offset": self.instruction_offset,
            "mitre_technique": self.mitre_technique,
        }


@dataclass
class ForensicReport:
    program_name: str = ""
    program_hash: str = ""
    analysis_time: float = 0.0
    indicators: List[ForensicIndicator] = field(default_factory=list)
    helper_usage: Dict[str, int] = field(default_factory=dict)
    complexity: Dict[str, int] = field(default_factory=dict)
    overall_risk: str = "low"

    def to_dict(self) -> dict:
        return {
            "program_name": self.program_name,
            "program_hash": self.program_hash,
            "analysis_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                           time.localtime(self.analysis_time)),
            "overall_risk": self.overall_risk,
            "indicator_count": len(self.indicators),
            "indicators": [i.to_dict() for i in self.indicators],
            "helper_usage": self.helper_usage,
            "complexity": self.complexity,
        }


# Suspicious helper combinations
SUSPICIOUS_HELPER_PATTERNS = {
    "credential_theft": {
        "helpers": {BPFHelper.PROBE_READ, BPFHelper.GET_CURRENT_COMM,
                    BPFHelper.PERF_EVENT_OUTPUT},
        "description": "Reads kernel memory and exfiltrates via perf events",
        "severity": "critical",
        "mitre": "T1056.001",
    },
    "process_hiding": {
        "helpers": {BPFHelper.OVERRIDE_RETURN, BPFHelper.GET_CURRENT_PID_TGID},
        "description": "Overrides syscall return values based on PID — process hiding",
        "severity": "critical",
        "mitre": "T1564.001",
    },
    "network_exfil": {
        "helpers": {BPFHelper.SKB_STORE_BYTES, BPFHelper.REDIRECT},
        "description": "Modifies and redirects network packets",
        "severity": "high",
        "mitre": "T1048",
    },
    "data_exfil_ringbuf": {
        "helpers": {BPFHelper.RINGBUF_RESERVE, BPFHelper.RINGBUF_SUBMIT,
                    BPFHelper.PROBE_READ},
        "description": "Reads kernel memory and exfiltrates via ringbuf",
        "severity": "critical",
        "mitre": "T1005",
    },
    "syscall_tampering": {
        "helpers": {BPFHelper.OVERRIDE_RETURN},
        "description": "Overrides syscall return values — can hide operations or force errors",
        "severity": "critical",
        "mitre": "T1014",
    },
    "persistence_tailcall": {
        "helpers": {BPFHelper.TAIL_CALL},
        "description": "Uses tail calls for program chaining — possible persistence",
        "severity": "medium",
        "mitre": "T1547",
    },
    "signal_injection": {
        "helpers": {BPFHelper.SEND_SIGNAL, BPFHelper.GET_CURRENT_PID_TGID},
        "description": "Sends signals to processes based on PID — can kill security tools",
        "severity": "high",
        "mitre": "T1489",
    },
}

# Suspicious attach points
SUSPICIOUS_ATTACH_POINTS = {
    "__x64_sys_getdents64": ("Process/file hiding", "critical", "T1564.001"),
    "__x64_sys_getdents": ("Process/file hiding (32-bit)", "critical", "T1564.001"),
    "pam_sm_authenticate": ("Credential harvesting", "critical", "T1056.001"),
    "auth_password": ("SSH credential harvesting", "critical", "T1056.001"),
    "__x64_sys_bpf": ("BPF syscall interception — self-hiding", "critical", "T1014"),
    "security_bprm_check": ("Execution control — LSM hook", "high", "T1059"),
    "tcp_v4_connect": ("Network connection monitoring", "medium", "T1071"),
    "inet_csk_accept": ("Incoming connection interception", "medium", "T1557"),
    "do_unlinkat": ("File deletion interception", "medium", "T1070.004"),
    "__x64_sys_kill": ("Signal interception", "medium", "T1489"),
    "io_submit_sqes": ("io_uring monitoring — evasion indicator", "high", "T1562.001"),
}


class BPFForensicAnalyzer:
    """Analyze BPF programs for malicious behavior."""

    def __init__(self):
        self.reports: List[ForensicReport] = []

    def analyze_program(self, program: BPFProgram) -> ForensicReport:
        """Full forensic analysis of a BPF program."""
        report = ForensicReport(
            program_name=program.name,
            program_hash=hashlib.sha256(program.bytecode()).hexdigest(),
            analysis_time=time.time(),
            complexity=program.complexity_estimate(),
        )

        # Extract helper calls
        helpers_used = self._extract_helpers(program)
        report.helper_usage = {
            BPFHelper(h).name if h in BPFHelper._value2member_map_ else f"unknown_{h}": count
            for h, count in helpers_used.items()
        }

        # Check helper patterns
        helper_set = set(helpers_used.keys())
        for pattern_name, pattern in SUSPICIOUS_HELPER_PATTERNS.items():
            if pattern["helpers"].issubset(helper_set):
                report.indicators.append(ForensicIndicator(
                    indicator_type=f"suspicious_helpers_{pattern_name}",
                    severity=pattern["severity"],
                    confidence=0.85,
                    description=pattern["description"],
                    evidence=f"Helpers: {', '.join(BPFHelper(h).name for h in pattern['helpers'] if h in BPFHelper._value2member_map_)}",
                    mitre_technique=pattern["mitre"],
                ))

        # Check attach point
        if program.attach_point in SUSPICIOUS_ATTACH_POINTS:
            desc, sev, mitre = SUSPICIOUS_ATTACH_POINTS[program.attach_point]
            report.indicators.append(ForensicIndicator(
                indicator_type="suspicious_attach_point",
                severity=sev,
                confidence=0.90,
                description=desc,
                evidence=f"Attached to: {program.attach_point}",
                mitre_technique=mitre,
            ))

        # Check for override_return usage
        if BPFHelper.OVERRIDE_RETURN in helper_set:
            report.indicators.append(ForensicIndicator(
                indicator_type="override_return",
                severity="critical",
                confidence=0.95,
                description="Uses bpf_override_return to modify syscall return values. "
                            "This is the primary mechanism for process/file hiding rootkits.",
                evidence="Helper call: bpf_override_return",
                mitre_technique="T1014",
            ))

        # Check program type risk
        high_risk_types = {
            BPFProgType.KPROBE: "Kprobe — can hook any kernel function",
            BPFProgType.TRACING: "Tracing — advanced kernel function hooking",
            BPFProgType.XDP: "XDP — driver-level packet interception",
            BPFProgType.LSM: "LSM — can override security policy decisions",
        }
        if program.prog_type in high_risk_types:
            report.indicators.append(ForensicIndicator(
                indicator_type="high_risk_program_type",
                severity="medium",
                confidence=0.70,
                description=high_risk_types[program.prog_type],
                evidence=f"Program type: {program.prog_type.name}",
            ))

        # Check bytecode size anomalies
        if program.insn_count() > 1000:
            report.indicators.append(ForensicIndicator(
                indicator_type="large_program",
                severity="low",
                confidence=0.50,
                description=f"Unusually large BPF program ({program.insn_count()} instructions). "
                            "Complex programs may indicate advanced rootkit behavior.",
                evidence=f"{program.insn_count()} instructions, "
                         f"{len(program.bytecode())} bytes",
            ))

        # Compute overall risk
        report.overall_risk = self._compute_risk(report.indicators)
        self.reports.append(report)
        return report

    def _extract_helpers(self, program: BPFProgram) -> Dict[int, int]:
        """Extract all BPF helper function calls from bytecode."""
        helpers = {}
        for insn in program.instructions:
            if (insn.opcode & 0x07) == BPFClass.JMP:
                if (insn.opcode & 0xF0) == BPFJmp.CALL:
                    helpers[insn.imm] = helpers.get(insn.imm, 0) + 1
        return helpers

    def _compute_risk(self, indicators: List[ForensicIndicator]) -> str:
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if not indicators:
            return "low"
        max_sev = max(severity_scores.get(i.severity, 0) for i in indicators)
        weighted = sum(
            severity_scores.get(i.severity, 0) * i.confidence
            for i in indicators
        )
        if max_sev >= 4 or weighted >= 8:
            return "critical"
        if max_sev >= 3 or weighted >= 5:
            return "high"
        if max_sev >= 2 or weighted >= 3:
            return "medium"
        return "low"

    def analyze_bytecode_raw(self, bytecode: bytes, name: str = "unknown",
                             prog_type: BPFProgType = BPFProgType.KPROBE,
                             attach_point: str = "") -> ForensicReport:
        """Analyze raw BPF bytecode (from bpftool prog dump)."""
        insns = []
        for i in range(0, len(bytecode), 8):
            chunk = bytecode[i:i+8]
            if len(chunk) == 8:
                insn = BPFInsn.decode(chunk)
                if insn:
                    insns.append(insn)

        prog = BPFProgram(
            name=name, prog_type=prog_type,
            instructions=insns, attach_point=attach_point,
        )
        return self.analyze_program(prog)

    def batch_analyze(self, programs: List[BPFProgram]) -> List[ForensicReport]:
        """Analyze multiple programs and return sorted by risk."""
        reports = [self.analyze_program(p) for p in programs]
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        reports.sort(key=lambda r: risk_order.get(r.overall_risk, 4))
        return reports
