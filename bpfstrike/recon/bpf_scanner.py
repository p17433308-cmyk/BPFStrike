"""
BPF reconnaissance — enumerate loaded BPF programs, maps, and links on a
target system. Identifies security tools, detects exploitable BPF features,
and maps the kernel BPF attack surface.

On Linux this uses /proc/bpf*, /sys/kernel/debug/tracing, and bpftool output
parsing. On any platform it can analyze bpftool JSON output and BPF program
dumps provided as files.
"""
import os
import json
import re
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import IntEnum

from ..core.bpf_bytecode import BPFProgType, BPFMapType


@dataclass
class BPFProgramInfo:
    prog_id: int = 0
    prog_type: str = ""
    name: str = ""
    tag: str = ""
    loaded_at: str = ""
    uid: int = 0
    bytes_xlated: int = 0
    bytes_jited: int = 0
    bytes_memlock: int = 0
    map_ids: List[int] = field(default_factory=list)
    btf_id: int = 0
    pids: List[Dict] = field(default_factory=list)
    attach_type: str = ""
    suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.prog_id, "type": self.prog_type, "name": self.name,
            "tag": self.tag, "loaded_at": self.loaded_at, "uid": self.uid,
            "bytes_xlated": self.bytes_xlated, "bytes_jited": self.bytes_jited,
            "map_ids": self.map_ids, "pids": self.pids,
            "suspicious": self.suspicious,
            "suspicion_reasons": self.suspicion_reasons,
        }


@dataclass
class BPFMapInfo:
    map_id: int = 0
    map_type: str = ""
    name: str = ""
    key_size: int = 0
    value_size: int = 0
    max_entries: int = 0
    bytes_memlock: int = 0
    frozen: bool = False
    pids: List[Dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.map_id, "type": self.map_type, "name": self.name,
            "key_size": self.key_size, "value_size": self.value_size,
            "max_entries": self.max_entries, "frozen": self.frozen,
            "pids": self.pids,
        }


@dataclass
class BPFLinkInfo:
    link_id: int = 0
    link_type: str = ""
    prog_id: int = 0
    attach_type: str = ""
    target: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.link_id, "type": self.link_type,
            "prog_id": self.prog_id, "attach_type": self.attach_type,
            "target": self.target,
        }


@dataclass
class KernelBPFCapabilities:
    """What BPF features the kernel supports — defines the attack surface."""
    kernel_version: str = ""
    bpf_enabled: bool = False
    unprivileged_bpf: bool = False
    jit_enabled: bool = False
    jit_harden: int = 0
    prog_types: List[str] = field(default_factory=list)
    map_types: List[str] = field(default_factory=list)
    helper_functions: List[str] = field(default_factory=list)
    btf_available: bool = False
    ringbuf_available: bool = False
    bpf_lsm_available: bool = False

    def to_dict(self) -> dict:
        return {
            "kernel_version": self.kernel_version,
            "bpf_enabled": self.bpf_enabled,
            "unprivileged_bpf": self.unprivileged_bpf,
            "jit_enabled": self.jit_enabled,
            "jit_harden": self.jit_harden,
            "prog_types_available": len(self.prog_types),
            "map_types_available": len(self.map_types),
            "btf_available": self.btf_available,
            "ringbuf_available": self.ringbuf_available,
            "bpf_lsm_available": self.bpf_lsm_available,
        }

    def attack_surface_score(self) -> int:
        """Score 0-100 indicating how exploitable the BPF subsystem is."""
        score = 0
        if self.bpf_enabled:
            score += 20
        if self.unprivileged_bpf:
            score += 30
        if self.jit_enabled and self.jit_harden == 0:
            score += 15
        if self.ringbuf_available:
            score += 10
        if self.bpf_lsm_available:
            score += 10
        if "kprobe" in [p.lower() for p in self.prog_types]:
            score += 10
        if "xdp" in [p.lower() for p in self.prog_types]:
            score += 5
        return min(score, 100)


@dataclass
class SecurityToolDetection:
    tool_name: str = ""
    detected: bool = False
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    prog_ids: List[int] = field(default_factory=list)
    map_ids: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name, "detected": self.detected,
            "confidence": f"{self.confidence:.0%}",
            "evidence": self.evidence,
            "prog_ids": self.prog_ids, "map_ids": self.map_ids,
        }


@dataclass
class ReconResult:
    scan_time: float = 0.0
    capabilities: KernelBPFCapabilities = field(default_factory=KernelBPFCapabilities)
    programs: List[BPFProgramInfo] = field(default_factory=list)
    maps: List[BPFMapInfo] = field(default_factory=list)
    links: List[BPFLinkInfo] = field(default_factory=list)
    security_tools: List[SecurityToolDetection] = field(default_factory=list)
    suspicious_programs: List[BPFProgramInfo] = field(default_factory=list)

    def summary(self) -> dict:
        return {
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.scan_time)),
            "kernel": self.capabilities.kernel_version,
            "bpf_attack_surface_score": self.capabilities.attack_surface_score(),
            "total_programs": len(self.programs),
            "total_maps": len(self.maps),
            "total_links": len(self.links),
            "security_tools_detected": sum(1 for t in self.security_tools if t.detected),
            "suspicious_programs": len(self.suspicious_programs),
        }


class BPFScanner:
    """Enumerate and analyze the BPF subsystem on a target host."""

    def __init__(self):
        self.result = ReconResult(scan_time=time.time())

    def scan_capabilities(self) -> KernelBPFCapabilities:
        """Detect kernel BPF capabilities from /proc and /sys."""
        caps = KernelBPFCapabilities()

        # Kernel version
        try:
            with open("/proc/version") as f:
                ver = f.read().strip()
                m = re.search(r"(\d+\.\d+\.\d+)", ver)
                caps.kernel_version = m.group(1) if m else ver[:40]
        except (OSError, IOError):
            caps.kernel_version = "unknown"

        # BPF sysctl settings
        sysctl_paths = {
            "/proc/sys/kernel/unprivileged_bpf_disabled": "unprivileged_bpf",
            "/proc/sys/net/core/bpf_jit_enable": "jit_enabled",
            "/proc/sys/net/core/bpf_jit_harden": "jit_harden",
        }
        for path, attr in sysctl_paths.items():
            try:
                with open(path) as f:
                    val = int(f.read().strip())
                    if attr == "unprivileged_bpf":
                        caps.unprivileged_bpf = (val == 0)
                    elif attr == "jit_enabled":
                        caps.jit_enabled = (val >= 1)
                    elif attr == "jit_harden":
                        caps.jit_harden = val
            except (OSError, IOError, ValueError):
                pass

        # Check if BPF is available
        caps.bpf_enabled = os.path.exists("/sys/fs/bpf") or caps.kernel_version != "unknown"

        # Enumerate prog types from kernel version
        major_minor = caps.kernel_version.split(".")[:2]
        try:
            major, minor = int(major_minor[0]), int(major_minor[1])
            if major >= 4:
                caps.prog_types.extend(["socket_filter", "kprobe", "sched_cls", "tracepoint"])
            if major >= 4 and minor >= 8:
                caps.prog_types.append("xdp")
            if major >= 4 and minor >= 10:
                caps.prog_types.append("cgroup_skb")
            if major >= 5 and minor >= 2:
                caps.btf_available = True
            if major >= 5 and minor >= 8:
                caps.ringbuf_available = True
                caps.prog_types.append("tracing")
            if major >= 5 and minor >= 7:
                caps.bpf_lsm_available = True
                caps.prog_types.append("lsm")
        except (ValueError, IndexError):
            pass

        self.result.capabilities = caps
        return caps

    def parse_bpftool_progs(self, json_data: str) -> List[BPFProgramInfo]:
        """Parse bpftool prog list --json output."""
        try:
            progs_raw = json.loads(json_data)
        except json.JSONDecodeError:
            return []

        programs = []
        for p in progs_raw:
            prog = BPFProgramInfo(
                prog_id=p.get("id", 0),
                prog_type=p.get("type", ""),
                name=p.get("name", ""),
                tag=p.get("tag", ""),
                loaded_at=p.get("loaded_at", ""),
                uid=p.get("uid", 0),
                bytes_xlated=p.get("bytes_xlated", 0),
                bytes_jited=p.get("bytes_jited", 0),
                bytes_memlock=p.get("bytes_memlock", 0),
                map_ids=p.get("map_ids", []),
                btf_id=p.get("btf_id", 0),
                pids=p.get("pids", []),
            )
            self._analyze_program_suspicion(prog)
            programs.append(prog)

        self.result.programs = programs
        return programs

    def parse_bpftool_maps(self, json_data: str) -> List[BPFMapInfo]:
        """Parse bpftool map list --json output."""
        try:
            maps_raw = json.loads(json_data)
        except json.JSONDecodeError:
            return []

        maps = []
        for m in maps_raw:
            bpf_map = BPFMapInfo(
                map_id=m.get("id", 0),
                map_type=m.get("type", ""),
                name=m.get("name", ""),
                key_size=m.get("key_size", 0),
                value_size=m.get("value_size", 0),
                max_entries=m.get("max_entries", 0),
                bytes_memlock=m.get("bytes_memlock", 0),
                frozen=m.get("frozen", False),
                pids=m.get("pids", []),
            )
            maps.append(bpf_map)

        self.result.maps = maps
        return maps

    def _analyze_program_suspicion(self, prog: BPFProgramInfo):
        """Flag suspicious BPF programs — potential rootkits or malware."""
        suspicious_names = [
            "hide", "hook", "intercept", "inject", "exfil", "keylog",
            "cred", "rootkit", "backdoor", "stealth", "evasion",
        ]
        suspicious_types = ["kprobe", "tracing", "raw_tracepoint"]

        for pattern in suspicious_names:
            if pattern in prog.name.lower():
                prog.suspicious = True
                prog.suspicion_reasons.append(f"Name contains '{pattern}'")

        if prog.prog_type.lower() in suspicious_types and prog.uid == 0:
            if not any(pid.get("comm", "").startswith(("systemd", "kernel"))
                       for pid in prog.pids):
                prog.suspicious = True
                prog.suspicion_reasons.append(
                    f"Root-owned {prog.prog_type} without known system owner"
                )

        if prog.bytes_xlated > 50000:
            prog.suspicious = True
            prog.suspicion_reasons.append(
                f"Unusually large program ({prog.bytes_xlated} bytes)"
            )

        if len(prog.map_ids) > 10:
            prog.suspicious = True
            prog.suspicion_reasons.append(
                f"Many maps attached ({len(prog.map_ids)})"
            )

    def detect_security_tools(self) -> List[SecurityToolDetection]:
        """Identify eBPF-based security tools from program/map names."""
        from ..evasion.security_bypass import SECURITY_TOOL_SIGNATURES

        detections = []
        for tool_name, sigs in SECURITY_TOOL_SIGNATURES.items():
            detection = SecurityToolDetection(tool_name=tool_name)
            evidence = []
            matched_progs = []
            matched_maps = []

            for prog in self.result.programs:
                for sig_name in sigs["prog_names"]:
                    if sig_name in prog.name:
                        evidence.append(f"Program '{prog.name}' matches signature '{sig_name}'")
                        matched_progs.append(prog.prog_id)

            for bpf_map in self.result.maps:
                for sig_name in sigs["map_names"]:
                    if sig_name in bpf_map.name:
                        evidence.append(f"Map '{bpf_map.name}' matches signature '{sig_name}'")
                        matched_maps.append(bpf_map.map_id)

            if evidence:
                detection.detected = True
                detection.confidence = min(len(evidence) / 3.0, 1.0)
                detection.evidence = evidence
                detection.prog_ids = matched_progs
                detection.map_ids = matched_maps

            detections.append(detection)

        self.result.security_tools = detections
        self.result.suspicious_programs = [
            p for p in self.result.programs if p.suspicious
        ]
        return detections

    def full_scan(self, bpftool_progs_json: str = "",
                  bpftool_maps_json: str = "") -> ReconResult:
        """Run full BPF reconnaissance."""
        self.scan_capabilities()
        if bpftool_progs_json:
            self.parse_bpftool_progs(bpftool_progs_json)
        if bpftool_maps_json:
            self.parse_bpftool_maps(bpftool_maps_json)
        self.detect_security_tools()
        return self.result
