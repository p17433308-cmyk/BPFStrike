"""BPFStrike — eBPF Offensive Security Framework."""
__version__ = "4.0.0"

from .core.bpf_bytecode import (
    BPFInsn, BPFProgram, BPFMapDef,
    BPFClass, BPFSize, BPFMode, BPFOp, BPFJmp, BPFSrc,
    BPFReg, BPFHelper, BPFProgType, BPFMapType, XDPAction,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    and64_imm, or64_imm, xor64_imm, lsh64_imm, rsh64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, jge_imm, ja,
)

from .core.elf_generator import generate_bpf_elf, hash_bpf_program

from .attacks.offensive_programs import (
    AttackProgram, ALL_ATTACKS, generate_all_attacks,
    generate_syscall_hook, generate_process_hider,
    generate_xdp_interceptor, generate_credential_harvester,
    generate_container_escape, generate_file_hider,
    generate_keylogger, generate_bpf_self_hider,
)

from .evasion.security_bypass import (
    SECURITY_TOOL_SIGNATURES, ALTERNATIVE_SYSCALLS, IO_URING_EVASION,
    EVASION_ATTACKS, generate_all_evasion_attacks,
    generate_io_uring_evasion, generate_map_corruption,
)

from .recon.bpf_scanner import (
    BPFScanner, ReconResult,
    BPFProgramInfo, BPFMapInfo, BPFLinkInfo,
    KernelBPFCapabilities, SecurityToolDetection,
)

from .forensics.bpf_analyzer import (
    BPFForensicAnalyzer, ForensicReport, ForensicIndicator,
    SUSPICIOUS_HELPER_PATTERNS, SUSPICIOUS_ATTACH_POINTS,
)

from .verifier.bypass_patterns import (
    VerifierBypass, VERIFIER_CVES, ALL_BYPASSES,
    generate_all_bypasses, generate_complexity_bomb,
    generate_alu32_bounds_confusion, generate_pointer_arith_confusion,
)

from .composer.rootkit_builder import (
    RootkitComposer, ComposedRootkit, RootkitComponent,
    RootkitConfig,
)

from .detection.rule_generator import (
    DetectionRuleGenerator, DetectionRule, RuleSet,
)

from .obfuscator.bytecode_obfuscator import (
    BytecodeObfuscator, ObfuscationResult, ObfuscationConfig,
    ObfuscationDetectionResult,
)

from .compiler.payload_compiler import (
    PayloadCompiler, CompiledPayload, PayloadModule,
    MODULE_TYPES, EXFIL_METHODS, EVASION_MODES,
)

from .antiforensics.countermeasures import (
    AntiForensicEngine, CountermeasureProgram, CountermeasureSuite,
    ALL_COUNTERMEASURES, PRESETS as AF_PRESETS,
    ANALYSIS_TOOLS, SECURITY_TOOLS, VM_INDICATORS,
)

from .chainer.exploit_chain import (
    ExploitChainer, ExploitChainResult, KernelFingerprint,
    CVEMatch, ChainStage, KERNEL_CVE_MAP, KERNEL_CAPABILITIES,
)

from .loader.stealth_loader import (
    StealthLoader, LoaderConfig, LoadResult,
    build_map_create_attr, build_prog_load_attr,
    build_ptrace_shellcode, build_memfd_shellcode,
    PTRACE_SHELLCODE, BPFCmd, Syscall,
)

from .validator.verifier_harness import (
    VerifierHarness, ValidationResult, ValidationIssue,
)

__all__ = [
    "BPFInsn", "BPFProgram", "BPFMapDef",
    "BPFClass", "BPFSize", "BPFMode", "BPFOp", "BPFJmp", "BPFSrc",
    "BPFReg", "BPFHelper", "BPFProgType", "BPFMapType", "XDPAction",
    "mov64_imm", "mov64_reg", "add64_imm", "sub64_imm",
    "and64_imm", "or64_imm", "xor64_imm", "lsh64_imm", "rsh64_imm",
    "ldx_mem", "stx_mem", "st_mem", "lddw",
    "call_helper", "exit_prog", "jeq_imm", "jne_imm", "jgt_imm", "jge_imm", "ja",
    "generate_bpf_elf", "hash_bpf_program",
    "AttackProgram", "ALL_ATTACKS", "generate_all_attacks",
    "generate_syscall_hook", "generate_process_hider",
    "generate_xdp_interceptor", "generate_credential_harvester",
    "generate_container_escape", "generate_file_hider",
    "generate_keylogger", "generate_bpf_self_hider",
    "SECURITY_TOOL_SIGNATURES", "ALTERNATIVE_SYSCALLS", "IO_URING_EVASION",
    "EVASION_ATTACKS", "generate_all_evasion_attacks",
    "generate_io_uring_evasion", "generate_map_corruption",
    "BPFScanner", "ReconResult",
    "BPFProgramInfo", "BPFMapInfo", "BPFLinkInfo",
    "KernelBPFCapabilities", "SecurityToolDetection",
    "BPFForensicAnalyzer", "ForensicReport", "ForensicIndicator",
    "SUSPICIOUS_HELPER_PATTERNS", "SUSPICIOUS_ATTACH_POINTS",
    "VerifierBypass", "VERIFIER_CVES", "ALL_BYPASSES",
    "generate_all_bypasses", "generate_complexity_bomb",
    "generate_alu32_bounds_confusion", "generate_pointer_arith_confusion",
    "RootkitComposer", "ComposedRootkit", "RootkitComponent", "RootkitConfig",
    "DetectionRuleGenerator", "DetectionRule", "RuleSet",
    "BytecodeObfuscator", "ObfuscationResult", "ObfuscationConfig",
    "ObfuscationDetectionResult",
    "PayloadCompiler", "CompiledPayload", "PayloadModule",
    "MODULE_TYPES", "EXFIL_METHODS", "EVASION_MODES",
    "AntiForensicEngine", "CountermeasureProgram", "CountermeasureSuite",
    "ALL_COUNTERMEASURES", "AF_PRESETS",
    "ANALYSIS_TOOLS", "SECURITY_TOOLS", "VM_INDICATORS",
    "ExploitChainer", "ExploitChainResult", "KernelFingerprint",
    "CVEMatch", "ChainStage", "KERNEL_CVE_MAP", "KERNEL_CAPABILITIES",
    "StealthLoader", "LoaderConfig", "LoadResult",
    "build_map_create_attr", "build_prog_load_attr",
    "build_ptrace_shellcode", "build_memfd_shellcode",
    "PTRACE_SHELLCODE", "BPFCmd", "Syscall",
    "VerifierHarness", "ValidationResult", "ValidationIssue",
]
