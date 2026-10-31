"""
BPF bytecode construction — real eBPF instruction encoding.

Each eBPF instruction is 8 bytes:
  [opcode:8][dst_reg:4][src_reg:4][offset:16][immediate:32]

This module builds real BPF bytecode that can be loaded into the Linux kernel
via bpf(2) syscall. All opcodes, register assignments, and instruction
sequences follow the eBPF ISA specification.

Reference: https://www.kernel.org/doc/html/latest/bpf/instruction-set.html
"""
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import IntEnum


# ============================================================================
# BPF Instruction Classes
# ============================================================================
class BPFClass(IntEnum):
    LD = 0x00
    LDX = 0x01
    ST = 0x02
    STX = 0x03
    ALU = 0x04
    JMP = 0x05
    JMP32 = 0x06
    ALU64 = 0x07


class BPFSize(IntEnum):
    W = 0x00   # 32-bit
    H = 0x08   # 16-bit
    B = 0x10   # 8-bit
    DW = 0x18  # 64-bit


class BPFMode(IntEnum):
    IMM = 0x00
    ABS = 0x20
    IND = 0x40
    MEM = 0x60
    ATOMIC = 0xC0


class BPFOp(IntEnum):
    ADD = 0x00
    SUB = 0x10
    MUL = 0x20
    DIV = 0x30
    OR = 0x40
    AND = 0x50
    LSH = 0x60
    RSH = 0x70
    NEG = 0x80
    MOD = 0x90
    XOR = 0xA0
    MOV = 0xB0
    ARSH = 0xC0
    END = 0xD0


class BPFJmp(IntEnum):
    JA = 0x00
    JEQ = 0x10
    JGT = 0x20
    JGE = 0x30
    JSET = 0x40
    JNE = 0x50
    JSGT = 0x60
    JSGE = 0x70
    CALL = 0x80
    EXIT = 0x90
    JLT = 0xA0
    JLE = 0xB0
    JSLT = 0xC0
    JSLE = 0xD0


class BPFSrc(IntEnum):
    IMM = 0x00  # use immediate
    REG = 0x08  # use src_reg


class BPFReg(IntEnum):
    R0 = 0
    R1 = 1
    R2 = 2
    R3 = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10  # frame pointer (read-only)


# BPF helper function IDs
class BPFHelper(IntEnum):
    UNSPEC = 0
    MAP_LOOKUP_ELEM = 1
    MAP_UPDATE_ELEM = 2
    MAP_DELETE_ELEM = 3
    PROBE_READ = 4
    KTIME_GET_NS = 5
    TRACE_PRINTK = 6
    GET_PRANDOM_U32 = 7
    GET_SMP_PROCESSOR_ID = 8
    SKB_STORE_BYTES = 9
    L3_CSUM_REPLACE = 10
    L4_CSUM_REPLACE = 11
    TAIL_CALL = 12
    CLONE_REDIRECT = 13
    GET_CURRENT_PID_TGID = 14
    GET_CURRENT_UID_GID = 15
    GET_CURRENT_COMM = 16
    GET_CGROUP_CLASSID = 17
    SKB_VLAN_PUSH = 18
    SKB_VLAN_POP = 19
    SKB_GET_TUNNEL_KEY = 20
    SKB_SET_TUNNEL_KEY = 21
    PERF_EVENT_READ = 22
    REDIRECT = 23
    GET_ROUTE_REALM = 24
    PERF_EVENT_OUTPUT = 25
    SKB_LOAD_BYTES = 26
    GET_STACKID = 27
    CSUM_DIFF = 28
    SKB_GET_TUNNEL_OPT = 29
    SKB_SET_TUNNEL_OPT = 30
    PROBE_READ_STR = 45
    GET_CURRENT_TASK = 35
    OVERRIDE_RETURN = 58
    SEND_SIGNAL = 109
    RINGBUF_OUTPUT = 130
    RINGBUF_RESERVE = 131
    RINGBUF_SUBMIT = 132
    D_PATH = 147


# BPF program types
class BPFProgType(IntEnum):
    UNSPEC = 0
    SOCKET_FILTER = 1
    KPROBE = 2
    SCHED_CLS = 3
    SCHED_ACT = 4
    TRACEPOINT = 5
    XDP = 6
    PERF_EVENT = 7
    CGROUP_SKB = 8
    CGROUP_SOCK = 9
    LWT_IN = 10
    LWT_OUT = 11
    LWT_XMIT = 12
    SOCK_OPS = 13
    SK_SKB = 14
    CGROUP_DEVICE = 15
    SK_MSG = 16
    RAW_TRACEPOINT = 17
    CGROUP_SOCK_ADDR = 18
    LWT_SEG6LOCAL = 19
    LIRC_MODE2 = 20
    SK_REUSEPORT = 21
    FLOW_DISSECTOR = 22
    CGROUP_SYSCTL = 23
    RAW_TRACEPOINT_WRITABLE = 24
    CGROUP_SOCKOPT = 25
    TRACING = 26
    STRUCT_OPS = 27
    EXT = 28
    LSM = 29
    SK_LOOKUP = 30
    SYSCALL = 31


# BPF map types
class BPFMapType(IntEnum):
    UNSPEC = 0
    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3
    PERF_EVENT_ARRAY = 4
    PERCPU_HASH = 5
    PERCPU_ARRAY = 6
    STACK_TRACE = 7
    CGROUP_ARRAY = 8
    LRU_HASH = 9
    LRU_PERCPU_HASH = 10
    LPM_TRIE = 11
    ARRAY_OF_MAPS = 12
    HASH_OF_MAPS = 13
    DEVMAP = 14
    SOCKMAP = 15
    CPUMAP = 16
    XSKMAP = 17
    SOCKHASH = 18
    CGROUP_STORAGE = 19
    REUSEPORT_SOCKARRAY = 20
    PERCPU_CGROUP_STORAGE = 21
    QUEUE = 22
    STACK = 23
    SK_STORAGE = 24
    DEVMAP_HASH = 25
    STRUCT_OPS = 26
    RINGBUF = 27
    INODE_STORAGE = 28
    TASK_STORAGE = 29


# XDP action codes
class XDPAction(IntEnum):
    ABORTED = 0
    DROP = 1
    PASS = 2
    TX = 3
    REDIRECT = 4


# ============================================================================
# BPF Instruction
# ============================================================================
@dataclass
class BPFInsn:
    """Single eBPF instruction — 8 bytes encoded."""
    opcode: int = 0
    dst_reg: int = 0
    src_reg: int = 0
    offset: int = 0
    imm: int = 0

    def encode(self) -> bytes:
        regs = ((self.src_reg & 0xF) << 4) | (self.dst_reg & 0xF)
        return struct.pack("<BBHI",
                           self.opcode, regs,
                           self.offset & 0xFFFF,
                           self.imm & 0xFFFFFFFF)

    def encode_signed(self) -> bytes:
        regs = ((self.src_reg & 0xF) << 4) | (self.dst_reg & 0xF)
        return struct.pack("<BBhi", self.opcode, regs, self.offset, self.imm)

    @classmethod
    def decode(cls, data: bytes) -> Optional["BPFInsn"]:
        if len(data) < 8:
            return None
        opcode, regs, offset, imm = struct.unpack("<BBhi", data[:8])
        return cls(
            opcode=opcode,
            dst_reg=regs & 0xF,
            src_reg=(regs >> 4) & 0xF,
            offset=offset,
            imm=imm,
        )

    def disassemble(self) -> str:
        cls = self.opcode & 0x07
        if cls == BPFClass.ALU64 or cls == BPFClass.ALU:
            return self._dis_alu()
        elif cls == BPFClass.JMP or cls == BPFClass.JMP32:
            return self._dis_jmp()
        elif cls in (BPFClass.LD, BPFClass.LDX):
            return self._dis_ld()
        elif cls in (BPFClass.ST, BPFClass.STX):
            return self._dis_st()
        return f"unknown opcode=0x{self.opcode:02x}"

    def _dis_alu(self):
        width = "64" if (self.opcode & 0x07) == BPFClass.ALU64 else "32"
        op = self.opcode & 0xF0
        src = "imm" if (self.opcode & 0x08) == 0 else f"r{self.src_reg}"
        op_names = {0x00: "add", 0x10: "sub", 0x20: "mul", 0x30: "div",
                    0x40: "or", 0x50: "and", 0x60: "lsh", 0x70: "rsh",
                    0x80: "neg", 0x90: "mod", 0xA0: "xor", 0xB0: "mov",
                    0xC0: "arsh", 0xD0: "end"}
        name = op_names.get(op, f"alu_0x{op:02x}")
        if src == "imm":
            return f"{name}{width} r{self.dst_reg}, {self.imm}"
        return f"{name}{width} r{self.dst_reg}, {src}"

    def _dis_jmp(self):
        op = self.opcode & 0xF0
        if op == BPFJmp.CALL:
            return f"call {self.imm}"
        if op == BPFJmp.EXIT:
            return "exit"
        if op == BPFJmp.JA:
            return f"ja +{self.offset}"
        jmp_names = {0x10: "jeq", 0x20: "jgt", 0x30: "jge", 0x40: "jset",
                     0x50: "jne", 0x60: "jsgt", 0x70: "jsge", 0xA0: "jlt",
                     0xB0: "jle", 0xC0: "jslt", 0xD0: "jsle"}
        name = jmp_names.get(op, f"jmp_0x{op:02x}")
        src = f"r{self.src_reg}" if (self.opcode & 0x08) else str(self.imm)
        return f"{name} r{self.dst_reg}, {src}, +{self.offset}"

    def _dis_ld(self):
        size_map = {0x00: "w", 0x08: "h", 0x10: "b", 0x18: "dw"}
        sz = size_map.get(self.opcode & 0x18, "?")
        if (self.opcode & 0x07) == BPFClass.LDX:
            return f"ldx{sz} r{self.dst_reg}, [r{self.src_reg}+{self.offset}]"
        if (self.opcode & 0xE0) == BPFMode.IMM:
            return f"ld{sz} r{self.dst_reg}, {self.imm}"
        return f"ld{sz} r{self.dst_reg}, [r{self.src_reg}+{self.offset}]"

    def _dis_st(self):
        size_map = {0x00: "w", 0x08: "h", 0x10: "b", 0x18: "dw"}
        sz = size_map.get(self.opcode & 0x18, "?")
        if (self.opcode & 0x07) == BPFClass.STX:
            return f"stx{sz} [r{self.dst_reg}+{self.offset}], r{self.src_reg}"
        return f"st{sz} [r{self.dst_reg}+{self.offset}], {self.imm}"


# ============================================================================
# Instruction builders — ergonomic wrappers
# ============================================================================
def mov64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.MOV | BPFSrc.IMM, dst, 0, 0, imm)


def mov64_reg(dst: int, src: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.MOV | BPFSrc.REG, dst, src, 0, 0)


def add64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.ADD | BPFSrc.IMM, dst, 0, 0, imm)


def add64_reg(dst: int, src: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.ADD | BPFSrc.REG, dst, src, 0, 0)


def sub64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.SUB | BPFSrc.IMM, dst, 0, 0, imm)


def and64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.AND | BPFSrc.IMM, dst, 0, 0, imm)


def or64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.OR | BPFSrc.IMM, dst, 0, 0, imm)


def xor64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.XOR | BPFSrc.IMM, dst, 0, 0, imm)


def lsh64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.LSH | BPFSrc.IMM, dst, 0, 0, imm)


def rsh64_imm(dst: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ALU64 | BPFOp.RSH | BPFSrc.IMM, dst, 0, 0, imm)


def ldx_mem(size: int, dst: int, src: int, offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.LDX | size | BPFMode.MEM, dst, src, offset, 0)


def stx_mem(size: int, dst: int, src: int, offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.STX | size | BPFMode.MEM, dst, src, offset, 0)


def st_mem(size: int, dst: int, offset: int, imm: int) -> BPFInsn:
    return BPFInsn(BPFClass.ST | size | BPFMode.MEM, dst, 0, offset, imm)


def lddw(dst: int, imm: int) -> List[BPFInsn]:
    """Load 64-bit immediate — takes two instruction slots."""
    lo = imm & 0xFFFFFFFF
    hi = (imm >> 32) & 0xFFFFFFFF
    return [
        BPFInsn(BPFClass.LD | BPFSize.DW | BPFMode.IMM, dst, 0, 0, lo),
        BPFInsn(0, 0, 0, 0, hi),
    ]


def call_helper(helper_id: int) -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.CALL, 0, 0, 0, helper_id)


def exit_prog() -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.EXIT, 0, 0, 0, 0)


def jeq_imm(dst: int, imm: int, offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.JEQ | BPFSrc.IMM, dst, 0, offset, imm)


def jne_imm(dst: int, imm: int, offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.JNE | BPFSrc.IMM, dst, 0, offset, imm)


def jgt_imm(dst: int, imm: int, offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.JGT | BPFSrc.IMM, dst, 0, offset, imm)


def jge_imm(dst: int, imm: int, offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.JGE | BPFSrc.IMM, dst, 0, offset, imm)


def ja(offset: int) -> BPFInsn:
    return BPFInsn(BPFClass.JMP | BPFJmp.JA, 0, 0, offset, 0)


# ============================================================================
# BPF Map Definition
# ============================================================================
@dataclass
class BPFMapDef:
    name: str = ""
    map_type: BPFMapType = BPFMapType.HASH
    key_size: int = 4
    value_size: int = 4
    max_entries: int = 1024
    map_flags: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.map_type.name,
            "key_size": self.key_size,
            "value_size": self.value_size,
            "max_entries": self.max_entries,
            "flags": self.map_flags,
        }


# ============================================================================
# BPF Program
# ============================================================================
@dataclass
class BPFProgram:
    """Complete BPF program with instructions, maps, and metadata."""
    name: str = ""
    prog_type: BPFProgType = BPFProgType.KPROBE
    instructions: List[BPFInsn] = field(default_factory=list)
    maps: List[BPFMapDef] = field(default_factory=list)
    license: str = "GPL"
    attach_point: str = ""
    description: str = ""

    def add_insn(self, insn) -> "BPFProgram":
        if isinstance(insn, list):
            self.instructions.extend(insn)
        else:
            self.instructions.append(insn)
        return self

    def add_map(self, map_def: BPFMapDef) -> "BPFProgram":
        self.maps.append(map_def)
        return self

    def bytecode(self) -> bytes:
        buf = b""
        for insn in self.instructions:
            buf += insn.encode()
        return buf

    def insn_count(self) -> int:
        return len(self.instructions)

    def disassemble(self) -> str:
        lines = []
        for i, insn in enumerate(self.instructions):
            lines.append(f"  {i:4d}: {insn.disassemble()}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.prog_type.name,
            "attach_point": self.attach_point,
            "instruction_count": self.insn_count(),
            "bytecode_size": len(self.bytecode()),
            "maps": [m.to_dict() for m in self.maps],
            "license": self.license,
            "description": self.description,
        }

    def complexity_estimate(self) -> Dict[str, int]:
        """Estimate verifier complexity — instructions, branches, calls."""
        branches = 0
        calls = 0
        mem_accesses = 0
        for insn in self.instructions:
            cls = insn.opcode & 0x07
            if cls in (BPFClass.JMP, BPFClass.JMP32):
                op = insn.opcode & 0xF0
                if op == BPFJmp.CALL:
                    calls += 1
                elif op != BPFJmp.EXIT:
                    branches += 1
            elif cls in (BPFClass.LD, BPFClass.LDX, BPFClass.ST, BPFClass.STX):
                mem_accesses += 1
        return {
            "instructions": self.insn_count(),
            "branches": branches,
            "helper_calls": calls,
            "memory_accesses": mem_accesses,
            "estimated_states": min(self.insn_count() * (branches + 1), 1_000_000),
        }
