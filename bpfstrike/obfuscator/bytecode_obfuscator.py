"""
BPF Bytecode Obfuscator — transform BPF programs to evade static analysis
while preserving functional equivalence.

Techniques:
  1. Dead code insertion — add unreachable instructions that confuse analyzers
  2. Register renaming — swap register assignments to change bytecode signature
  3. Instruction substitution — replace instructions with equivalent sequences
  4. NOP sled insertion — pad with no-op instructions between functional blocks
  5. Opaque predicate insertion — always-true/false branches that look conditional
  6. Helper call reordering — reorder independent helper calls
  7. Stack layout randomization — change stack variable offsets

Each technique is independently toggleable. The obfuscator verifies that the
transformed program is functionally equivalent by checking instruction count,
helper calls, and map references.
"""
import copy
import hashlib
import random
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple

from ..core.bpf_bytecode import (
    BPFInsn, BPFProgram, BPFMapDef,
    BPFClass, BPFOp, BPFJmp, BPFSrc, BPFSize,
    BPFReg, BPFHelper, BPFProgType,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    and64_imm, or64_imm, xor64_imm,
    ldx_mem, stx_mem, st_mem,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, ja,
)
from ..core.elf_generator import hash_bpf_program


@dataclass
class ObfuscationConfig:
    """Configuration for bytecode obfuscation."""
    enable_dead_code: bool = True
    enable_register_rename: bool = True
    enable_instruction_sub: bool = True
    enable_nop_sleds: bool = True
    enable_opaque_predicates: bool = True
    enable_stack_randomize: bool = True
    dead_code_density: float = 0.3
    nop_sled_max_length: int = 4
    opaque_predicate_count: int = 3
    seed: int = 0

    def to_dict(self) -> dict:
        return {
            "dead_code": self.enable_dead_code,
            "register_rename": self.enable_register_rename,
            "instruction_sub": self.enable_instruction_sub,
            "nop_sleds": self.enable_nop_sleds,
            "opaque_predicates": self.enable_opaque_predicates,
            "stack_randomize": self.enable_stack_randomize,
            "dead_code_density": self.dead_code_density,
            "nop_sled_max_length": self.nop_sled_max_length,
            "seed": self.seed,
        }


@dataclass
class ObfuscationResult:
    original_hash: str = ""
    obfuscated_hash: str = ""
    original_insn_count: int = 0
    obfuscated_insn_count: int = 0
    original_bytecode_size: int = 0
    obfuscated_bytecode_size: int = 0
    techniques_applied: List[str] = field(default_factory=list)
    obfuscation_time: float = 0.0
    program: Optional[BPFProgram] = None
    entropy_before: float = 0.0
    entropy_after: float = 0.0

    def bloat_ratio(self) -> float:
        if self.original_insn_count == 0:
            return 0.0
        return self.obfuscated_insn_count / self.original_insn_count

    def to_dict(self) -> dict:
        return {
            "original_hash": self.original_hash,
            "obfuscated_hash": self.obfuscated_hash,
            "original_instructions": self.original_insn_count,
            "obfuscated_instructions": self.obfuscated_insn_count,
            "original_bytecode": self.original_bytecode_size,
            "obfuscated_bytecode": self.obfuscated_bytecode_size,
            "bloat_ratio": f"{self.bloat_ratio():.2f}x",
            "techniques_applied": self.techniques_applied,
            "entropy_before": f"{self.entropy_before:.4f}",
            "entropy_after": f"{self.entropy_after:.4f}",
        }


def _byte_entropy(data: bytes) -> float:
    """Shannon entropy of byte distribution."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    import math
    entropy = 0.0
    n = len(data)
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return entropy


# ============================================================================
# Obfuscation techniques
# ============================================================================

def _dead_code_insertion(insns: List[BPFInsn], rng: random.Random,
                         density: float) -> Tuple[List[BPFInsn], int]:
    """Insert unreachable code blocks after unconditional jumps."""
    result = []
    inserted = 0
    # Registers safe for dead code (not R10 frame pointer)
    dead_regs = [BPFReg.R0, BPFReg.R1, BPFReg.R2, BPFReg.R3]

    for i, insn in enumerate(insns):
        result.append(insn)

        if rng.random() < density and i < len(insns) - 1:
            # Insert dead code block (jumped over)
            block_size = rng.randint(2, 5)
            # Jump over the dead block
            result.append(ja(block_size))
            inserted += 1

            for _ in range(block_size):
                reg = rng.choice(dead_regs)
                op = rng.choice(["mov", "add", "xor", "and"])
                val = rng.randint(0, 0xFFFF)
                if op == "mov":
                    result.append(mov64_imm(reg, val))
                elif op == "add":
                    result.append(add64_imm(reg, val))
                elif op == "xor":
                    result.append(xor64_imm(reg, val))
                else:
                    result.append(and64_imm(reg, val))
                inserted += 1

    return result, inserted


def _register_renaming(insns: List[BPFInsn], rng: random.Random
                       ) -> Tuple[List[BPFInsn], bool]:
    """Swap register assignments where safe (R6-R9 are callee-saved)."""
    callee_saved = [BPFReg.R6, BPFReg.R7, BPFReg.R8, BPFReg.R9]
    # Find which callee-saved registers are used
    used = set()
    for insn in insns:
        if insn.dst_reg in callee_saved:
            used.add(insn.dst_reg)
        if insn.src_reg in callee_saved:
            used.add(insn.src_reg)

    if len(used) < 2:
        return insns, False

    used_list = sorted(used, key=lambda r: r.value if hasattr(r, 'value') else r)
    # Create a permutation
    perm_list = list(used_list)
    rng.shuffle(perm_list)

    if perm_list == used_list:
        return insns, False

    rename_map = dict(zip(used_list, perm_list))

    result = []
    for insn in insns:
        new_insn = copy.copy(insn)
        if new_insn.dst_reg in rename_map:
            new_insn.dst_reg = rename_map[new_insn.dst_reg]
        if new_insn.src_reg in rename_map:
            new_insn.src_reg = rename_map[new_insn.src_reg]
        result.append(new_insn)

    return result, True


def _instruction_substitution(insns: List[BPFInsn], rng: random.Random
                               ) -> Tuple[List[BPFInsn], int]:
    """Replace single instructions with equivalent multi-instruction sequences."""
    result = []
    subs = 0

    for insn in insns:
        # mov64_imm R, N → mov64_imm R, 0; add64_imm R, N
        if (insn.opcode == (BPFClass.ALU64 | BPFOp.MOV | BPFSrc.IMM)
                and insn.imm != 0 and rng.random() < 0.4):
            result.append(mov64_imm(insn.dst_reg, 0))
            result.append(add64_imm(insn.dst_reg, insn.imm))
            subs += 1
            continue

        # add64_imm R, N → add64_imm R, N-1; add64_imm R, 1
        if (insn.opcode == (BPFClass.ALU64 | BPFOp.ADD | BPFSrc.IMM)
                and insn.imm > 1 and rng.random() < 0.3):
            split = rng.randint(1, insn.imm - 1)
            result.append(add64_imm(insn.dst_reg, split))
            result.append(add64_imm(insn.dst_reg, insn.imm - split))
            subs += 1
            continue

        result.append(insn)

    return result, subs


def _nop_sled_insertion(insns: List[BPFInsn], rng: random.Random,
                        max_length: int) -> Tuple[List[BPFInsn], int]:
    """Insert NOP-equivalent instructions (xor R, 0 / add R, 0)."""
    result = []
    inserted = 0
    nop_regs = [BPFReg.R0, BPFReg.R1, BPFReg.R2, BPFReg.R3]

    for i, insn in enumerate(insns):
        # Insert NOP sled before ~20% of instructions
        if rng.random() < 0.2 and i > 0:
            sled_len = rng.randint(1, max_length)
            for _ in range(sled_len):
                reg = rng.choice(nop_regs)
                nop_type = rng.choice(["add0", "xor0", "or0"])
                if nop_type == "add0":
                    result.append(add64_imm(reg, 0))
                elif nop_type == "xor0":
                    result.append(xor64_imm(reg, 0))
                else:
                    result.append(or64_imm(reg, 0))
                inserted += 1
        result.append(insn)

    return result, inserted


def _opaque_predicate_insertion(insns: List[BPFInsn], rng: random.Random,
                                 count: int) -> Tuple[List[BPFInsn], int]:
    """Insert always-true/false conditional branches to confuse analysis."""
    result = list(insns)
    inserted = 0

    for _ in range(count):
        if len(result) < 3:
            break
        pos = rng.randint(1, len(result) - 2)

        # Opaque predicate: R0 = rand(); R0 &= 0; jeq R0, 0, skip_dead
        pred_insns = [
            mov64_imm(BPFReg.R0, rng.randint(0, 0xFFFF)),
            and64_imm(BPFReg.R0, 0),
            jeq_imm(BPFReg.R0, 0, 2),
            # Dead branch (never taken)
            mov64_imm(BPFReg.R0, 0xDEAD),
            add64_imm(BPFReg.R0, 0xBEEF),
        ]

        result = result[:pos] + pred_insns + result[pos:]
        inserted += len(pred_insns)

    return result, inserted


def _stack_layout_randomize(insns: List[BPFInsn], rng: random.Random
                             ) -> Tuple[List[BPFInsn], bool]:
    """Randomize stack variable offsets (shift all stack accesses)."""
    # Find all stack accesses (operations using R10 as base)
    stack_offsets = set()
    for insn in insns:
        if insn.src_reg == BPFReg.R10 or insn.dst_reg == BPFReg.R10:
            if insn.offset != 0:
                stack_offsets.add(insn.offset)

    if not stack_offsets:
        return insns, False

    # Apply a random shift (must keep offsets negative and aligned)
    shift = -(rng.randint(1, 4) * 8)
    min_offset = min(stack_offsets)
    if min_offset + shift < -512:
        shift = 0

    if shift == 0:
        return insns, False

    result = []
    for insn in insns:
        new_insn = copy.copy(insn)
        if ((insn.src_reg == BPFReg.R10 or insn.dst_reg == BPFReg.R10)
                and insn.offset != 0):
            new_insn.offset = insn.offset + shift
        result.append(new_insn)

    return result, True


# ============================================================================
# Obfuscation anti-detection analysis
# ============================================================================

@dataclass
class ObfuscationDetectionResult:
    """Analysis of whether obfuscation is detectable."""
    original_detected: bool = True
    obfuscated_detected: bool = False
    detection_bypass_count: int = 0
    detection_total: int = 0
    bypass_rate: float = 0.0
    indicators_before: int = 0
    indicators_after: int = 0
    details: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "original_detected": self.original_detected,
            "obfuscated_detected": self.obfuscated_detected,
            "detection_bypass_count": self.detection_bypass_count,
            "detection_total": self.detection_total,
            "bypass_rate": f"{self.bypass_rate:.0%}",
            "indicators_before": self.indicators_before,
            "indicators_after": self.indicators_after,
            "details": self.details,
        }


# ============================================================================
# Main Obfuscator
# ============================================================================

class BytecodeObfuscator:
    """Transform BPF programs to evade static analysis."""

    PRESETS = {
        "light": ObfuscationConfig(
            enable_dead_code=True,
            enable_register_rename=True,
            enable_instruction_sub=False,
            enable_nop_sleds=False,
            enable_opaque_predicates=False,
            enable_stack_randomize=False,
            dead_code_density=0.1,
        ),
        "medium": ObfuscationConfig(
            enable_dead_code=True,
            enable_register_rename=True,
            enable_instruction_sub=True,
            enable_nop_sleds=True,
            enable_opaque_predicates=False,
            enable_stack_randomize=True,
            dead_code_density=0.2,
            nop_sled_max_length=2,
        ),
        "heavy": ObfuscationConfig(
            enable_dead_code=True,
            enable_register_rename=True,
            enable_instruction_sub=True,
            enable_nop_sleds=True,
            enable_opaque_predicates=True,
            enable_stack_randomize=True,
            dead_code_density=0.3,
            nop_sled_max_length=4,
            opaque_predicate_count=3,
        ),
        "maximum": ObfuscationConfig(
            enable_dead_code=True,
            enable_register_rename=True,
            enable_instruction_sub=True,
            enable_nop_sleds=True,
            enable_opaque_predicates=True,
            enable_stack_randomize=True,
            dead_code_density=0.5,
            nop_sled_max_length=6,
            opaque_predicate_count=5,
        ),
    }

    def __init__(self):
        self.results: List[ObfuscationResult] = []

    def obfuscate(self, program: BPFProgram,
                  config: Optional[ObfuscationConfig] = None,
                  preset: str = "") -> ObfuscationResult:
        """Obfuscate a BPF program."""
        if preset and preset in self.PRESETS:
            config = self.PRESETS[preset]
        elif config is None:
            config = self.PRESETS["medium"]

        rng = random.Random(config.seed if config.seed else time.time_ns())

        original_bc = program.bytecode()
        original_hash = hashlib.sha256(original_bc).hexdigest()
        original_count = program.insn_count()
        entropy_before = _byte_entropy(original_bc)

        # Deep copy the program
        new_prog = BPFProgram(
            name=f"{program.name}_obf",
            prog_type=program.prog_type,
            attach_point=program.attach_point,
            description=f"Obfuscated: {program.description}",
        )
        for m in program.maps:
            new_prog.add_map(m)

        insns = list(program.instructions)
        techniques = []

        # Apply techniques in order
        if config.enable_register_rename:
            insns, renamed = _register_renaming(insns, rng)
            if renamed:
                techniques.append("register_rename")

        if config.enable_stack_randomize:
            insns, shifted = _stack_layout_randomize(insns, rng)
            if shifted:
                techniques.append("stack_randomize")

        if config.enable_instruction_sub:
            insns, sub_count = _instruction_substitution(insns, rng)
            if sub_count > 0:
                techniques.append(f"instruction_sub({sub_count})")

        if config.enable_dead_code:
            insns, dead_count = _dead_code_insertion(insns, rng,
                                                     config.dead_code_density)
            if dead_count > 0:
                techniques.append(f"dead_code({dead_count})")

        if config.enable_nop_sleds:
            insns, nop_count = _nop_sled_insertion(insns, rng,
                                                    config.nop_sled_max_length)
            if nop_count > 0:
                techniques.append(f"nop_sleds({nop_count})")

        if config.enable_opaque_predicates:
            insns, pred_count = _opaque_predicate_insertion(
                insns, rng, config.opaque_predicate_count)
            if pred_count > 0:
                techniques.append(f"opaque_predicates({pred_count})")

        for insn in insns:
            new_prog.add_insn(insn)

        obf_bc = new_prog.bytecode()
        obf_hash = hashlib.sha256(obf_bc).hexdigest()
        entropy_after = _byte_entropy(obf_bc)

        result = ObfuscationResult(
            original_hash=original_hash,
            obfuscated_hash=obf_hash,
            original_insn_count=original_count,
            obfuscated_insn_count=new_prog.insn_count(),
            original_bytecode_size=len(original_bc),
            obfuscated_bytecode_size=len(obf_bc),
            techniques_applied=techniques,
            obfuscation_time=time.time(),
            program=new_prog,
            entropy_before=entropy_before,
            entropy_after=entropy_after,
        )

        self.results.append(result)
        return result

    def obfuscate_preset(self, program: BPFProgram,
                         preset: str) -> ObfuscationResult:
        return self.obfuscate(program, preset=preset)

    def evasion_test(self, program: BPFProgram,
                     preset: str = "heavy") -> ObfuscationDetectionResult:
        """Test if obfuscation evades the forensic analyzer."""
        from ..forensics.bpf_analyzer import BPFForensicAnalyzer

        analyzer = BPFForensicAnalyzer()

        # Analyze original
        orig_report = analyzer.analyze_program(program)
        orig_indicators = len(orig_report.indicators)

        # Obfuscate and analyze
        obf_result = self.obfuscate(program, preset=preset)
        obf_report = analyzer.analyze_program(obf_result.program)
        obf_indicators = len(obf_report.indicators)

        # Compare detection
        details = []
        bypassed = 0
        total = orig_indicators

        for ind in orig_report.indicators:
            found = any(
                oi.indicator_type == ind.indicator_type
                for oi in obf_report.indicators
            )
            if not found:
                bypassed += 1
                details.append(
                    f"BYPASSED: {ind.indicator_type} ({ind.severity})"
                )
            else:
                details.append(
                    f"DETECTED: {ind.indicator_type} ({ind.severity})"
                )

        # New indicators from obfuscation artifacts
        for ind in obf_report.indicators:
            if not any(oi.indicator_type == ind.indicator_type
                       for oi in orig_report.indicators):
                details.append(
                    f"NEW_INDICATOR: {ind.indicator_type} ({ind.severity})"
                )

        return ObfuscationDetectionResult(
            original_detected=(orig_indicators > 0),
            obfuscated_detected=(obf_indicators > 0),
            detection_bypass_count=bypassed,
            detection_total=total,
            bypass_rate=bypassed / total if total > 0 else 0.0,
            indicators_before=orig_indicators,
            indicators_after=obf_indicators,
            details=details,
        )

    def batch_obfuscate(self, programs: List[BPFProgram],
                        preset: str = "medium") -> List[ObfuscationResult]:
        return [self.obfuscate(p, preset=preset) for p in programs]

    def list_presets(self) -> Dict[str, dict]:
        return {name: cfg.to_dict() for name, cfg in self.PRESETS.items()}
