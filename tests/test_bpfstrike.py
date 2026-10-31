"""BPFStrike test suite — validates all modules produce real results."""
import json
import struct
import unittest

from bpfstrike.core.bpf_bytecode import (
    BPFInsn, BPFProgram, BPFMapDef,
    BPFClass, BPFSize, BPFMode, BPFOp, BPFJmp, BPFSrc,
    BPFReg, BPFHelper, BPFProgType, BPFMapType, XDPAction,
    mov64_imm, mov64_reg, add64_imm, sub64_imm,
    ldx_mem, stx_mem, st_mem, lddw,
    call_helper, exit_prog, jeq_imm, jne_imm, jgt_imm, jge_imm, ja,
)
from bpfstrike.core.elf_generator import generate_bpf_elf, hash_bpf_program
from bpfstrike.attacks.offensive_programs import (
    AttackProgram, ALL_ATTACKS, generate_all_attacks,
    generate_syscall_hook, generate_process_hider,
    generate_xdp_interceptor, generate_credential_harvester,
    generate_container_escape, generate_file_hider,
    generate_keylogger, generate_bpf_self_hider,
)
from bpfstrike.evasion.security_bypass import (
    SECURITY_TOOL_SIGNATURES, ALTERNATIVE_SYSCALLS, IO_URING_EVASION,
    EVASION_ATTACKS, generate_all_evasion_attacks,
    generate_io_uring_evasion, generate_map_corruption,
)
from bpfstrike.recon.bpf_scanner import (
    BPFScanner, BPFProgramInfo, BPFMapInfo, KernelBPFCapabilities,
    SecurityToolDetection, ReconResult,
)
from bpfstrike.forensics.bpf_analyzer import (
    BPFForensicAnalyzer, ForensicReport, ForensicIndicator,
    SUSPICIOUS_HELPER_PATTERNS, SUSPICIOUS_ATTACH_POINTS,
)
from bpfstrike.verifier.bypass_patterns import (
    VerifierBypass, VERIFIER_CVES, ALL_BYPASSES,
    generate_all_bypasses, generate_complexity_bomb,
    generate_alu32_bounds_confusion, generate_pointer_arith_confusion,
)


class TestBPFBytecode(unittest.TestCase):

    def test_insn_encode_decode(self):
        insn = mov64_imm(BPFReg.R0, 42)
        data = insn.encode()
        self.assertEqual(len(data), 8)
        decoded = BPFInsn.decode(data)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.imm & 0xFFFFFFFF, 42)

    def test_insn_encode_negative(self):
        insn = mov64_imm(BPFReg.R0, -1)
        data = insn.encode()
        self.assertEqual(len(data), 8)

    def test_lddw_two_insns(self):
        insns = lddw(BPFReg.R1, 0x1234567890ABCDEF)
        self.assertEqual(len(insns), 2)
        for i in insns:
            self.assertEqual(len(i.encode()), 8)

    def test_program_bytecode(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(mov64_imm(BPFReg.R0, 0))
        prog.add_insn(exit_prog())
        bc = prog.bytecode()
        self.assertEqual(len(bc), 16)
        self.assertIsInstance(bc, bytes)

    def test_program_disassemble(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(mov64_imm(BPFReg.R0, 0))
        prog.add_insn(exit_prog())
        text = prog.disassemble()
        self.assertIn("mov64", text.lower() if "MOV" not in text else text)

    def test_program_complexity(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(mov64_imm(BPFReg.R0, 0))
        prog.add_insn(jeq_imm(BPFReg.R0, 0, 1))
        prog.add_insn(add64_imm(BPFReg.R0, 1))
        prog.add_insn(exit_prog())
        c = prog.complexity_estimate()
        self.assertIn("instructions", c)
        self.assertIn("branches", c)
        self.assertEqual(c["instructions"], 4)
        self.assertGreaterEqual(c["branches"], 1)

    def test_map_def(self):
        m = BPFMapDef(name="test_map", map_type=BPFMapType.HASH,
                      key_size=4, value_size=8, max_entries=256)
        d = m.to_dict()
        self.assertEqual(d["name"], "test_map")
        self.assertEqual(d["key_size"], 4)

    def test_all_registers(self):
        for reg in BPFReg:
            insn = mov64_imm(reg, 0)
            self.assertEqual(len(insn.encode()), 8)

    def test_all_helpers_enum(self):
        self.assertGreater(len(BPFHelper), 30)
        self.assertIn(BPFHelper.MAP_LOOKUP_ELEM, BPFHelper)

    def test_all_prog_types_enum(self):
        self.assertGreater(len(BPFProgType), 20)
        self.assertIn(BPFProgType.KPROBE, BPFProgType)

    def test_all_map_types_enum(self):
        self.assertGreater(len(BPFMapType), 15)
        self.assertIn(BPFMapType.HASH, BPFMapType)


class TestELFGenerator(unittest.TestCase):

    def test_elf_generation(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(mov64_imm(BPFReg.R0, 0))
        prog.add_insn(exit_prog())
        elf = generate_bpf_elf(prog)
        self.assertTrue(elf.startswith(b"\x7fELF"))
        self.assertGreater(len(elf), 100)

    def test_elf_bpf_machine(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(exit_prog())
        elf = generate_bpf_elf(prog)
        e_machine = struct.unpack_from("<H", elf, 18)[0]
        self.assertEqual(e_machine, 247)

    def test_hash_deterministic(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(mov64_imm(BPFReg.R0, 0))
        prog.add_insn(exit_prog())
        h1 = hash_bpf_program(prog)
        h2 = hash_bpf_program(prog)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_elf_with_maps(self):
        prog = BPFProgram(name="test", prog_type=BPFProgType.KPROBE)
        prog.add_map(BPFMapDef(name="m", map_type=BPFMapType.HASH,
                               key_size=4, value_size=4, max_entries=16))
        prog.add_insn(exit_prog())
        elf = generate_bpf_elf(prog)
        self.assertTrue(elf.startswith(b"\x7fELF"))


class TestAttackPrograms(unittest.TestCase):

    def test_all_attacks_dict(self):
        self.assertEqual(len(ALL_ATTACKS), 8)

    def test_generate_all(self):
        attacks = generate_all_attacks()
        self.assertEqual(len(attacks), 8)
        for a in attacks:
            self.assertIsInstance(a, AttackProgram)
            self.assertTrue(a.name)
            self.assertTrue(a.category)
            self.assertTrue(a.mitre_technique)

    def test_each_attack_bytecode(self):
        for name, gen in ALL_ATTACKS.items():
            atk = gen()
            bc = atk.program.bytecode()
            self.assertGreater(len(bc), 0, f"{name} produced empty bytecode")
            self.assertEqual(len(bc) % 8, 0, f"{name} bytecode not 8-byte aligned")

    def test_each_attack_elf(self):
        for name, gen in ALL_ATTACKS.items():
            atk = gen()
            elf = generate_bpf_elf(atk.program)
            self.assertTrue(elf.startswith(b"\x7fELF"), f"{name} ELF invalid")

    def test_attack_to_dict(self):
        atk = generate_syscall_hook()
        d = atk.to_dict()
        self.assertIn("name", d)
        self.assertIn("bytecode_size", d)
        self.assertGreater(d["bytecode_size"], 0)
        self.assertIn("complexity", d)

    def test_syscall_hook_details(self):
        atk = generate_syscall_hook()
        self.assertEqual(atk.program.prog_type, BPFProgType.KPROBE)
        self.assertIn("sys_read", atk.program.attach_point)

    def test_process_hider_details(self):
        atk = generate_process_hider()
        self.assertIn("getdents", atk.program.attach_point)

    def test_xdp_interceptor_type(self):
        atk = generate_xdp_interceptor()
        self.assertEqual(atk.program.prog_type, BPFProgType.XDP)

    def test_credential_harvester_attach(self):
        atk = generate_credential_harvester()
        self.assertIn("pam", atk.program.attach_point)

    def test_container_escape_type(self):
        atk = generate_container_escape()
        self.assertEqual(atk.program.prog_type, BPFProgType.CGROUP_SKB)


class TestEvasion(unittest.TestCase):

    def test_security_tool_signatures(self):
        self.assertIn("falco", SECURITY_TOOL_SIGNATURES)
        self.assertIn("tetragon", SECURITY_TOOL_SIGNATURES)
        self.assertIn("tracee", SECURITY_TOOL_SIGNATURES)
        for tool, sigs in SECURITY_TOOL_SIGNATURES.items():
            self.assertIn("prog_names", sigs)
            self.assertIn("map_names", sigs)

    def test_alternative_syscalls(self):
        self.assertIn("file_read", ALTERNATIVE_SYSCALLS)
        self.assertIn("process_exec", ALTERNATIVE_SYSCALLS)
        self.assertIn("network", ALTERNATIVE_SYSCALLS)

    def test_io_uring_metadata(self):
        self.assertIn("operations", IO_URING_EVASION)
        self.assertGreater(len(IO_URING_EVASION["operations"]), 5)
        self.assertIn("cves", IO_URING_EVASION)

    def test_evasion_attacks(self):
        self.assertEqual(len(EVASION_ATTACKS), 5)
        attacks = generate_all_evasion_attacks()
        self.assertEqual(len(attacks), 5)
        for a in attacks:
            bc = a.program.bytecode()
            self.assertGreater(len(bc), 0)

    def test_io_uring_evasion_program(self):
        atk = generate_io_uring_evasion()
        self.assertEqual(atk.program.prog_type, BPFProgType.KPROBE)
        self.assertIn("io_submit", atk.program.attach_point)
        self.assertGreater(len(atk.program.maps), 0)

    def test_map_corruption_program(self):
        atk = generate_map_corruption()
        self.assertIn("bpf", atk.program.attach_point)


class TestRecon(unittest.TestCase):

    def test_scanner_init(self):
        scanner = BPFScanner()
        self.assertIsNotNone(scanner.result)

    def test_scan_capabilities(self):
        scanner = BPFScanner()
        caps = scanner.scan_capabilities()
        self.assertIsInstance(caps, KernelBPFCapabilities)
        self.assertIsInstance(caps.attack_surface_score(), int)
        self.assertGreaterEqual(caps.attack_surface_score(), 0)
        self.assertLessEqual(caps.attack_surface_score(), 100)

    def test_parse_bpftool_progs(self):
        scanner = BPFScanner()
        data = json.dumps([
            {"id": 1, "type": "kprobe", "name": "test_hook",
             "tag": "abc", "bytes_xlated": 200, "bytes_jited": 150,
             "map_ids": [1, 2], "pids": []},
            {"id": 2, "type": "tracing", "name": "rootkit_hide",
             "tag": "def", "bytes_xlated": 100, "pids": []},
        ])
        progs = scanner.parse_bpftool_progs(data)
        self.assertEqual(len(progs), 2)
        suspicious = [p for p in progs if p.suspicious]
        self.assertGreater(len(suspicious), 0)

    def test_parse_bpftool_maps(self):
        scanner = BPFScanner()
        data = json.dumps([
            {"id": 1, "type": "hash", "name": "events",
             "key_size": 4, "value_size": 64, "max_entries": 1024},
        ])
        maps_list = scanner.parse_bpftool_maps(data)
        self.assertEqual(len(maps_list), 1)
        self.assertEqual(maps_list[0].name, "events")

    def test_detect_security_tools(self):
        scanner = BPFScanner()
        scanner.scan_capabilities()
        data = json.dumps([
            {"id": 10, "type": "tracepoint", "name": "sys_enter",
             "tag": "x", "pids": []},
        ])
        scanner.parse_bpftool_progs(data)
        scanner.parse_bpftool_maps("[]")
        detections = scanner.detect_security_tools()
        self.assertIsInstance(detections, list)

    def test_recon_result_summary(self):
        scanner = BPFScanner()
        scanner.scan_capabilities()
        s = scanner.result.summary()
        self.assertIn("kernel", s)
        self.assertIn("bpf_attack_surface_score", s)

    def test_full_scan(self):
        scanner = BPFScanner()
        result = scanner.full_scan(bpftool_progs_json="[]",
                                   bpftool_maps_json="[]")
        self.assertIsInstance(result, ReconResult)

    def test_capabilities_to_dict(self):
        caps = KernelBPFCapabilities(kernel_version="5.15.0",
                                     bpf_enabled=True)
        d = caps.to_dict()
        self.assertEqual(d["kernel_version"], "5.15.0")
        self.assertTrue(d["bpf_enabled"])


class TestForensics(unittest.TestCase):

    def test_analyzer_init(self):
        analyzer = BPFForensicAnalyzer()
        self.assertEqual(len(analyzer.reports), 0)

    def test_analyze_attack_programs(self):
        analyzer = BPFForensicAnalyzer()
        attacks = generate_all_attacks()
        for atk in attacks:
            report = analyzer.analyze_program(atk.program)
            self.assertIsInstance(report, ForensicReport)
            self.assertTrue(report.program_name)
            self.assertTrue(report.program_hash)
            self.assertIn(report.overall_risk,
                          ["critical", "high", "medium", "low"])

    def test_batch_analyze(self):
        analyzer = BPFForensicAnalyzer()
        attacks = generate_all_attacks()
        reports = analyzer.batch_analyze([a.program for a in attacks])
        self.assertEqual(len(reports), 8)
        risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for i in range(len(reports) - 1):
            self.assertLessEqual(
                risk_order[reports[i].overall_risk],
                risk_order[reports[i + 1].overall_risk],
            )

    def test_report_to_dict(self):
        analyzer = BPFForensicAnalyzer()
        atk = generate_syscall_hook()
        report = analyzer.analyze_program(atk.program)
        d = report.to_dict()
        self.assertIn("program_name", d)
        self.assertIn("indicators", d)
        self.assertIn("overall_risk", d)

    def test_suspicious_helper_patterns(self):
        self.assertGreater(len(SUSPICIOUS_HELPER_PATTERNS), 5)
        for name, pat in SUSPICIOUS_HELPER_PATTERNS.items():
            self.assertIn("helpers", pat)
            self.assertIn("severity", pat)

    def test_suspicious_attach_points(self):
        self.assertGreater(len(SUSPICIOUS_ATTACH_POINTS), 5)
        self.assertIn("__x64_sys_getdents64", SUSPICIOUS_ATTACH_POINTS)
        self.assertIn("pam_sm_authenticate", SUSPICIOUS_ATTACH_POINTS)

    def test_analyze_bytecode_raw(self):
        prog = BPFProgram(name="raw", prog_type=BPFProgType.SOCKET_FILTER)
        prog.add_insn(mov64_imm(BPFReg.R0, 0))
        prog.add_insn(exit_prog())
        analyzer = BPFForensicAnalyzer()
        report = analyzer.analyze_bytecode_raw(prog.bytecode())
        self.assertIsInstance(report, ForensicReport)

    def test_forensic_indicator(self):
        ind = ForensicIndicator(
            indicator_type="test", severity="high",
            confidence=0.9, description="test indicator",
        )
        d = ind.to_dict()
        self.assertEqual(d["type"], "test")
        self.assertEqual(d["severity"], "high")


class TestVerifier(unittest.TestCase):

    def test_cve_database(self):
        self.assertEqual(len(VERIFIER_CVES), 6)
        for cve in VERIFIER_CVES:
            self.assertIn("cve", cve)
            self.assertIn("severity", cve)
            self.assertIn("cvss", cve)
            self.assertTrue(cve["cve"].startswith("CVE-"))

    def test_all_bypasses(self):
        self.assertEqual(len(ALL_BYPASSES), 8)
        bypasses = generate_all_bypasses()
        self.assertEqual(len(bypasses), 8)
        for bp in bypasses:
            self.assertIsInstance(bp, VerifierBypass)
            bc = bp.program.bytecode()
            self.assertGreater(len(bc), 0)

    def test_complexity_bomb(self):
        bp = generate_complexity_bomb()
        self.assertIn("complexity", bp.name.lower())
        c = bp.program.complexity_estimate()
        self.assertGreater(c["instructions"], 50)
        self.assertGreater(c["branches"], 10)

    def test_alu32_bounds(self):
        bp = generate_alu32_bounds_confusion()
        self.assertEqual(bp.cve, "CVE-2021-3490")
        self.assertTrue(bp.patched)

    def test_pointer_arith(self):
        bp = generate_pointer_arith_confusion()
        self.assertEqual(bp.cve, "CVE-2022-23222")
        self.assertTrue(bp.patched)

    def test_bypass_to_dict(self):
        bp = generate_complexity_bomb()
        d = bp.to_dict()
        self.assertIn("name", d)
        self.assertIn("instruction_count", d)
        self.assertGreater(d["instruction_count"], 0)

    def test_bypass_elf(self):
        for name, gen in ALL_BYPASSES.items():
            bp = gen()
            elf = generate_bpf_elf(bp.program)
            self.assertTrue(elf.startswith(b"\x7fELF"), f"{name} ELF invalid")


class TestComposer(unittest.TestCase):

    def test_compose_full(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        rootkit = composer.compose_preset("full")
        self.assertGreater(rootkit.component_count(), 5)
        self.assertGreater(rootkit.total_instructions(), 50)
        self.assertGreater(rootkit.total_bytecode(), 0)
        self.assertTrue(rootkit.rootkit_hash)

    def test_compose_minimal(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        rootkit = composer.compose_preset("minimal")
        self.assertGreater(rootkit.component_count(), 0)
        self.assertLess(rootkit.component_count(),
                        composer.compose_preset("full").component_count())

    def test_compose_all_presets(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        for preset in ["stealth", "full", "recon", "minimal"]:
            rootkit = composer.compose_preset(preset)
            self.assertTrue(rootkit.config.name)
            bc = rootkit.total_bytecode()
            self.assertGreater(bc, 0, f"Preset {preset} produced no bytecode")

    def test_compose_generates_elfs(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        rootkit = composer.compose_preset("stealth")
        elfs = rootkit.generate_elfs()
        self.assertGreater(len(elfs), 0)
        for fname, data in elfs.items():
            self.assertTrue(data.startswith(b"\x7fELF"), f"{fname} not valid ELF")

    def test_shared_maps(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        rootkit = composer.compose_preset("full")
        map_names = [m.name for m in rootkit.shared_maps]
        self.assertIn("rk_config", map_names)
        self.assertIn("rk_target_pids", map_names)
        self.assertIn("rk_killswitch", map_names)

    def test_rootkit_to_dict(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        rootkit = composer.compose_preset("full")
        d = rootkit.to_dict()
        self.assertIn("components", d)
        self.assertIn("total_bytecode", d)
        self.assertIn("rootkit_hash", d)

    def test_dispatcher_exists(self):
        from bpfstrike.composer.rootkit_builder import RootkitComposer
        composer = RootkitComposer()
        rootkit = composer.compose_preset("full")
        self.assertIsNotNone(rootkit.dispatcher)
        self.assertGreater(rootkit.dispatcher.insn_count(), 0)


class TestDetectionRules(unittest.TestCase):

    def test_generate_all_rules(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        rulesets = gen.generate_all()
        self.assertEqual(len(rulesets), 4)
        self.assertIn("yara", rulesets)
        self.assertIn("sigma", rulesets)
        self.assertIn("falco", rulesets)
        self.assertIn("snort", rulesets)

    def test_yara_rules(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        rs = gen.generate_format("yara")
        self.assertIsNotNone(rs)
        self.assertGreater(len(rs.rules), 5)
        for rule in rs.rules:
            self.assertIn("rule ", rule.rule_content)
            self.assertIn("meta:", rule.rule_content)
            self.assertIn("strings:", rule.rule_content)

    def test_sigma_rules(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        rs = gen.generate_format("sigma")
        self.assertIsNotNone(rs)
        self.assertGreater(len(rs.rules), 3)
        for rule in rs.rules:
            self.assertIn("title:", rule.rule_content)
            self.assertIn("detection:", rule.rule_content)

    def test_falco_rules(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        rs = gen.generate_format("falco")
        self.assertIsNotNone(rs)
        self.assertGreater(len(rs.rules), 5)
        for rule in rs.rules:
            self.assertIn("- rule:", rule.rule_content)
            self.assertIn("priority:", rule.rule_content)

    def test_snort_rules(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        rs = gen.generate_format("snort")
        self.assertIsNotNone(rs)
        self.assertGreater(len(rs.rules), 0)
        self.assertIn("alert", rs.rules[0].rule_content)

    def test_export(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        rs = gen.generate_format("yara")
        exported = rs.export()
        self.assertGreater(len(exported), 100)

    def test_total_rules(self):
        from bpfstrike.detection.rule_generator import DetectionRuleGenerator
        gen = DetectionRuleGenerator()
        gen.generate_all()
        self.assertGreater(gen.total_rules(), 15)


class TestObfuscator(unittest.TestCase):

    def test_obfuscate_single(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        atk = generate_syscall_hook()
        result = obf.obfuscate(atk.program, preset="medium")
        self.assertGreater(result.obfuscated_insn_count,
                          result.original_insn_count)
        self.assertNotEqual(result.original_hash, result.obfuscated_hash)
        self.assertGreater(len(result.techniques_applied), 0)

    def test_obfuscate_all_presets(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        atk = generate_process_hider()
        for preset in ["light", "medium", "heavy", "maximum"]:
            result = obf.obfuscate(atk.program, preset=preset)
            self.assertGreater(result.obfuscated_bytecode_size, 0)
            bc = result.program.bytecode()
            self.assertEqual(len(bc) % 8, 0)

    def test_bloat_ratio(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        atk = generate_syscall_hook()
        light = obf.obfuscate(atk.program, preset="light")
        heavy = obf.obfuscate(atk.program, preset="heavy")
        self.assertGreaterEqual(heavy.bloat_ratio(), light.bloat_ratio())

    def test_evasion_test(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        atk = generate_process_hider()
        evasion = obf.evasion_test(atk.program, preset="heavy")
        self.assertIsInstance(evasion.bypass_rate, float)
        self.assertGreaterEqual(evasion.indicators_before, 0)
        self.assertGreater(len(evasion.details), 0)

    def test_batch_obfuscate(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        attacks = generate_all_attacks()
        results = obf.batch_obfuscate(
            [a.program for a in attacks], preset="light")
        self.assertEqual(len(results), len(attacks))

    def test_entropy_changes(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        atk = generate_syscall_hook()
        result = obf.obfuscate(atk.program, preset="heavy")
        self.assertGreater(result.entropy_before, 0)
        self.assertGreater(result.entropy_after, 0)

    def test_result_to_dict(self):
        from bpfstrike.obfuscator.bytecode_obfuscator import BytecodeObfuscator
        obf = BytecodeObfuscator()
        atk = generate_syscall_hook()
        result = obf.obfuscate(atk.program, preset="medium")
        d = result.to_dict()
        self.assertIn("original_hash", d)
        self.assertIn("obfuscated_hash", d)
        self.assertIn("bloat_ratio", d)
        self.assertIn("techniques_applied", d)


class TestPackageExports(unittest.TestCase):

    def test_version(self):
        from bpfstrike import __version__
        self.assertEqual(__version__, "4.0.0")

    def test_all_exports(self):
        import bpfstrike
        self.assertGreater(len(bpfstrike.__all__), 80)

    def test_cli_import(self):
        from bpfstrike.cli import main
        self.assertTrue(callable(main))

    def test_new_module_imports(self):
        from bpfstrike import (RootkitComposer, DetectionRuleGenerator,
                               BytecodeObfuscator)
        self.assertTrue(callable(RootkitComposer))
        self.assertTrue(callable(DetectionRuleGenerator))
        self.assertTrue(callable(BytecodeObfuscator))


class TestPayloadCompiler(unittest.TestCase):
    def test_compile_example_stealth(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        result = compiler.compile_example("stealth_rootkit")
        self.assertFalse(result.errors)
        self.assertGreater(len(result.modules), 0)
        self.assertGreater(result.total_instructions(), 0)
        self.assertGreater(result.total_bytecode(), 0)

    def test_compile_all_examples(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        for name in compiler.EXAMPLE_SPECS:
            result = compiler.compile_example(name)
            self.assertFalse(result.errors, f"Example {name} had errors: {result.errors}")
            self.assertGreater(len(result.modules), 0)

    def test_compile_custom_spec(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        spec = {
            "payload": {
                "name": "test_payload",
                "targets": {"hide_pids": [1337]},
                "modules": [
                    {"type": "process_hider"},
                    {"type": "self_hider"},
                ],
                "options": {"kill_switch": True, "exfil": "ringbuf"},
            }
        }
        result = compiler.compile(spec)
        self.assertFalse(result.errors)
        self.assertEqual(len(result.modules), 2)

    def test_compile_generates_elfs(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        result = compiler.compile_example("credential_kit")
        elfs = result.generate_elfs()
        self.assertGreater(len(elfs), 0)
        for fname, data in elfs.items():
            self.assertTrue(fname.endswith(".o"))
            self.assertTrue(data[:4] == b'\x7fELF')

    def test_compile_invalid_module(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        spec = {"payload": {"modules": [{"type": "nonexistent"}]}}
        result = compiler.compile(spec)
        self.assertTrue(result.errors)

    def test_compile_empty_modules(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        spec = {"payload": {"modules": []}}
        result = compiler.compile(spec)
        self.assertTrue(result.errors)

    def test_payload_hash_deterministic(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        r1 = compiler.compile_example("stealth_rootkit")
        r2 = compiler.compile_example("stealth_rootkit")
        self.assertEqual(r1.payload_hash, r2.payload_hash)

    def test_all_module_types_compile(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler, MODULE_TYPES
        compiler = PayloadCompiler()
        for mod_type in MODULE_TYPES:
            spec = {"payload": {"name": f"test_{mod_type}",
                                "modules": [{"type": mod_type}],
                                "options": {"exfil": "ringbuf"}}}
            result = compiler.compile(spec)
            self.assertFalse(result.errors, f"Module {mod_type} failed")
            self.assertEqual(len(result.modules), 1)

    def test_to_dict(self):
        from bpfstrike.compiler.payload_compiler import PayloadCompiler
        compiler = PayloadCompiler()
        result = compiler.compile_example("stealth_rootkit")
        d = result.to_dict()
        self.assertIn("name", d)
        self.assertIn("payload_hash", d)
        self.assertIn("modules", d)
        self.assertIsInstance(d["modules"], list)


class TestAntiForensics(unittest.TestCase):
    def test_generate_all(self):
        from bpfstrike.antiforensics.countermeasures import AntiForensicEngine
        engine = AntiForensicEngine()
        suite = engine.generate_all()
        self.assertGreater(len(suite.programs), 0)
        self.assertGreater(suite.total_instructions(), 0)

    def test_all_presets(self):
        from bpfstrike.antiforensics.countermeasures import AntiForensicEngine, PRESETS
        engine = AntiForensicEngine()
        for preset_name in PRESETS:
            suite = engine.generate_suite(preset=preset_name)
            self.assertGreater(len(suite.programs), 0,
                               f"Preset {preset_name} produced no programs")

    def test_each_countermeasure(self):
        from bpfstrike.antiforensics.countermeasures import ALL_COUNTERMEASURES
        for name, gen_fn in ALL_COUNTERMEASURES.items():
            cm = gen_fn()
            self.assertGreater(cm.program.insn_count(), 0,
                               f"Countermeasure {name} has no instructions")
            bc = cm.program.bytecode()
            self.assertGreater(len(bc), 0)
            self.assertTrue(cm.name)
            self.assertTrue(cm.category)
            self.assertTrue(cm.description)

    def test_suite_generates_elfs(self):
        from bpfstrike.antiforensics.countermeasures import AntiForensicEngine
        engine = AntiForensicEngine()
        suite = engine.generate_suite(preset="minimal")
        elfs = suite.generate_elfs()
        self.assertGreater(len(elfs), 0)
        for fname, data in elfs.items():
            self.assertTrue(data[:4] == b'\x7fELF')

    def test_suite_hash_deterministic(self):
        from bpfstrike.antiforensics.countermeasures import AntiForensicEngine
        engine = AntiForensicEngine()
        s1 = engine.generate_suite(preset="stealth")
        s2 = engine.generate_suite(preset="stealth")
        self.assertEqual(s1.suite_hash, s2.suite_hash)

    def test_to_dict(self):
        from bpfstrike.antiforensics.countermeasures import AntiForensicEngine
        engine = AntiForensicEngine()
        suite = engine.generate_all()
        d = suite.to_dict()
        self.assertIn("total_programs", d)
        self.assertIn("suite_hash", d)
        self.assertIn("programs", d)

    def test_countermeasure_to_dict(self):
        from bpfstrike.antiforensics.countermeasures import generate_analysis_detector
        cm = generate_analysis_detector()
        d = cm.to_dict()
        self.assertIn("name", d)
        self.assertIn("category", d)
        self.assertIn("mitre", d)
        self.assertIn("instructions", d)


class TestExploitChainer(unittest.TestCase):
    def test_fingerprint_kernel(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        fp = chainer.fingerprint_kernel("5.10.42")
        self.assertEqual(fp.major, 5)
        self.assertEqual(fp.minor, 10)
        self.assertEqual(fp.patch, 42)
        self.assertTrue(fp.bpf_capable)
        self.assertEqual(fp.capabilities_era, "5.x_late")

    def test_fingerprint_kernel_4x(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        fp = chainer.fingerprint_kernel("4.19.0")
        self.assertEqual(fp.capabilities_era, "4.x")

    def test_fingerprint_kernel_6x(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        fp = chainer.fingerprint_kernel("6.5.0")
        self.assertEqual(fp.capabilities_era, "6.x")

    def test_match_cves(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        fp = chainer.fingerprint_kernel("5.10.0")
        matches = chainer.match_cves(fp)
        self.assertGreater(len(matches), 0)
        cve_ids = [m.cve_id for m in matches]
        self.assertIn("CVE-2021-3490", cve_ids)

    def test_no_match_old_kernel(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        fp = chainer.fingerprint_kernel("3.10.0")
        self.assertFalse(fp.bpf_capable)

    def test_execute_chain(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        result = chainer.execute_chain("5.10.0")
        self.assertTrue(result.success())
        self.assertGreater(len(result.stages), 0)
        self.assertIsNotNone(result.bypass_program)
        self.assertIsNotNone(result.rootkit)
        self.assertTrue(result.chain_hash)

    def test_execute_chain_6x(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        result = chainer.execute_chain("6.2.0", rootkit_preset="full")
        self.assertTrue(result.success())

    def test_chain_generates_elfs(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        result = chainer.execute_chain("5.10.0")
        elfs = result.generate_elfs()
        self.assertGreater(len(elfs), 0)
        for fname, data in elfs.items():
            self.assertTrue(data[:4] == b'\x7fELF')

    def test_to_dict(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        result = chainer.execute_chain("5.10.0")
        d = result.to_dict()
        self.assertIn("success", d)
        self.assertIn("stages", d)
        self.assertIn("chain_hash", d)

    def test_chain_old_kernel_fails(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        result = chainer.execute_chain("3.10.0")
        self.assertFalse(result.success())


class TestV3Exports(unittest.TestCase):
    def test_compiler_imports(self):
        from bpfstrike import PayloadCompiler, CompiledPayload, PayloadModule
        self.assertTrue(callable(PayloadCompiler))

    def test_antiforensics_imports(self):
        from bpfstrike import (AntiForensicEngine, CountermeasureProgram,
                               CountermeasureSuite)
        self.assertTrue(callable(AntiForensicEngine))

    def test_chainer_imports(self):
        from bpfstrike import (ExploitChainer, ExploitChainResult,
                               KernelFingerprint, CVEMatch)
        self.assertTrue(callable(ExploitChainer))

    def test_version(self):
        import bpfstrike
        self.assertEqual(bpfstrike.__version__, "4.0.0")


class TestStealthLoader(unittest.TestCase):
    def test_prepare_load_direct(self):
        from bpfstrike.loader.stealth_loader import StealthLoader, LoaderConfig
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        loader = StealthLoader(LoaderConfig(method="direct"))
        atk = generate_syscall_hook()
        result = loader.prepare_load(atk.program)
        self.assertTrue(result.success)
        self.assertEqual(result.method, "direct")
        self.assertGreater(len(result.syscall_sequence), 0)

    def test_prepare_load_memfd(self):
        from bpfstrike.loader.stealth_loader import StealthLoader, LoaderConfig
        from bpfstrike.attacks.offensive_programs import generate_process_hider
        loader = StealthLoader(LoaderConfig(method="memfd"))
        atk = generate_process_hider()
        result = loader.prepare_load(atk.program)
        self.assertTrue(result.success)
        memfd_calls = [s for s in result.syscall_sequence if s["syscall"] == "memfd_create"]
        self.assertGreater(len(memfd_calls), 0)

    def test_prepare_load_ptrace(self):
        from bpfstrike.loader.stealth_loader import StealthLoader, LoaderConfig
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        loader = StealthLoader(LoaderConfig(method="ptrace", target_pid=1234))
        atk = generate_syscall_hook()
        result = loader.prepare_load(atk.program)
        self.assertTrue(result.success)
        ptrace_calls = [s for s in result.syscall_sequence if s["syscall"] == "ptrace"]
        self.assertGreater(len(ptrace_calls), 0)

    def test_ptrace_requires_pid(self):
        from bpfstrike.loader.stealth_loader import StealthLoader, LoaderConfig
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        loader = StealthLoader(LoaderConfig(method="ptrace"))
        atk = generate_syscall_hook()
        result = loader.prepare_load(atk.program)
        self.assertFalse(result.success)
        self.assertIn("target_pid", result.error)

    def test_cleanup_actions(self):
        from bpfstrike.loader.stealth_loader import StealthLoader, LoaderConfig
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        loader = StealthLoader(LoaderConfig(method="direct", cleanup=True))
        atk = generate_syscall_hook()
        result = loader.prepare_load(atk.program)
        self.assertGreater(len(result.cleanup_actions), 0)
        self.assertIn("zero_stack_frame", result.cleanup_actions)

    def test_shellcode_generation(self):
        from bpfstrike.loader.stealth_loader import (
            build_ptrace_shellcode, build_memfd_shellcode)
        sc = build_ptrace_shellcode(5, 0x7FFE0000, 128)
        self.assertGreater(len(sc), 0)
        self.assertIn(b'\x0f\x05', sc)  # syscall instruction
        memfd = build_memfd_shellcode()
        self.assertGreater(len(memfd), 0)

    def test_map_create_attr(self):
        from bpfstrike.loader.stealth_loader import build_map_create_attr
        from bpfstrike.core.bpf_bytecode import BPFMapDef, BPFMapType
        m = BPFMapDef(name="test", map_type=BPFMapType.HASH,
                      key_size=4, value_size=8, max_entries=64)
        attr = build_map_create_attr(m)
        self.assertGreater(len(attr), 0)

    def test_batch_load(self):
        from bpfstrike.loader.stealth_loader import StealthLoader
        from bpfstrike.attacks.offensive_programs import generate_all_attacks
        loader = StealthLoader()
        attacks = generate_all_attacks()
        results = loader.prepare_batch_load([a.program for a in attacks])
        self.assertEqual(len(results), len(attacks))
        for r in results:
            self.assertTrue(r.success)

    def test_to_dict(self):
        from bpfstrike.loader.stealth_loader import StealthLoader
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        loader = StealthLoader()
        atk = generate_syscall_hook()
        result = loader.prepare_load(atk.program)
        d = result.to_dict()
        self.assertIn("success", d)
        self.assertIn("syscall_sequence", d)
        self.assertIn("method", d)


class TestCVEExploits(unittest.TestCase):
    def test_cve_2021_3490(self):
        from bpfstrike.verifier.bypass_patterns import generate_cve_2021_3490_exploit
        bp = generate_cve_2021_3490_exploit()
        self.assertEqual(bp.cve, "CVE-2021-3490")
        self.assertGreater(bp.program.insn_count(), 5)
        bc = bp.program.bytecode()
        self.assertGreater(len(bc), 0)
        self.assertTrue(len(bp.program.maps) > 0)

    def test_cve_2022_23222(self):
        from bpfstrike.verifier.bypass_patterns import generate_cve_2022_23222_exploit
        bp = generate_cve_2022_23222_exploit()
        self.assertEqual(bp.cve, "CVE-2022-23222")
        self.assertGreater(bp.program.insn_count(), 5)

    def test_cve_2023_2163(self):
        from bpfstrike.verifier.bypass_patterns import generate_cve_2023_2163_exploit
        bp = generate_cve_2023_2163_exploit()
        self.assertEqual(bp.cve, "CVE-2023-2163")
        self.assertGreater(bp.program.insn_count(), 10)

    def test_cve_2023_39191(self):
        from bpfstrike.verifier.bypass_patterns import generate_cve_2023_39191_exploit
        bp = generate_cve_2023_39191_exploit()
        self.assertEqual(bp.cve, "CVE-2023-39191")

    def test_cve_2024_2193(self):
        from bpfstrike.verifier.bypass_patterns import generate_cve_2024_2193_exploit
        bp = generate_cve_2024_2193_exploit()
        self.assertEqual(bp.cve, "CVE-2024-2193")
        bc = bp.program.bytecode()
        self.assertGreater(len(bc), 0)

    def test_all_cve_exploits_have_bytecode(self):
        from bpfstrike.verifier.bypass_patterns import ALL_BYPASSES
        for name, gen in ALL_BYPASSES.items():
            bp = gen()
            bc = bp.program.bytecode()
            self.assertGreater(len(bc), 0, f"{name} has no bytecode")

    def test_chainer_uses_cve_specific(self):
        from bpfstrike.chainer.exploit_chain import ExploitChainer
        chainer = ExploitChainer()
        result = chainer.execute_chain("5.10.0")
        self.assertTrue(result.success())
        self.assertIn("cve_2021_3490", result.bypass_program.name.lower().replace("-", "_"))


class TestLiveEvasion(unittest.TestCase):
    def test_live_map_wipe(self):
        from bpfstrike.evasion.security_bypass import generate_live_map_wipe
        atk = generate_live_map_wipe()
        self.assertEqual(atk.category, "live_evasion")
        self.assertGreater(atk.program.insn_count(), 10)
        bc = atk.program.bytecode()
        self.assertGreater(len(bc), 0)

    def test_prog_detach_attack(self):
        from bpfstrike.evasion.security_bypass import generate_prog_detach_attack
        atk = generate_prog_detach_attack()
        self.assertEqual(atk.category, "live_evasion")
        self.assertGreater(atk.program.insn_count(), 10)

    def test_tracepoint_hijack(self):
        from bpfstrike.evasion.security_bypass import generate_tracepoint_hijack
        atk = generate_tracepoint_hijack()
        self.assertEqual(atk.category, "live_evasion")
        self.assertEqual(atk.program.attach_point, "raw_syscalls/sys_enter")

    def test_all_evasion_attacks_count(self):
        from bpfstrike.evasion.security_bypass import generate_all_evasion_attacks
        attacks = generate_all_evasion_attacks()
        self.assertEqual(len(attacks), 5)

    def test_evasion_elfs(self):
        from bpfstrike.evasion.security_bypass import generate_all_evasion_attacks
        from bpfstrike.core.elf_generator import generate_bpf_elf
        for atk in generate_all_evasion_attacks():
            elf = generate_bpf_elf(atk.program)
            self.assertTrue(elf[:4] == b'\x7fELF')


class TestVerifierHarness(unittest.TestCase):
    def test_validate_valid_program(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        harness = VerifierHarness()
        atk = generate_syscall_hook()
        result = harness.validate(atk.program)
        self.assertTrue(result.valid)
        self.assertEqual(result.error_count(), 0)

    def test_validate_all_attacks(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.attacks.offensive_programs import generate_all_attacks
        harness = VerifierHarness()
        attacks = generate_all_attacks()
        results = harness.validate_batch([a.program for a in attacks])
        for r in results:
            self.assertTrue(r.valid, f"{r.program_name} failed: "
                            f"{[i.message for i in r.issues if i.severity == 'error']}")

    def test_validate_all_evasions(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.evasion.security_bypass import generate_all_evasion_attacks
        harness = VerifierHarness()
        evasions = generate_all_evasion_attacks()
        results = harness.validate_batch([a.program for a in evasions])
        for r in results:
            self.assertTrue(r.valid, f"{r.program_name} failed validation")

    def test_validate_bypasses(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.verifier.bypass_patterns import generate_all_bypasses
        harness = VerifierHarness()
        bypasses = generate_all_bypasses()
        results = harness.validate_batch([b.program for b in bypasses])
        for r in results:
            self.assertTrue(r.valid, f"{r.program_name} failed validation")

    def test_stats(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        harness = VerifierHarness()
        atk = generate_syscall_hook()
        result = harness.validate(atk.program)
        self.assertIn("instructions", result.stats)
        self.assertIn("branches", result.stats)
        self.assertIn("stack_depth", result.stats)
        self.assertGreater(result.stats["instructions"], 0)

    def test_summary(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.attacks.offensive_programs import generate_all_attacks
        harness = VerifierHarness()
        for a in generate_all_attacks():
            harness.validate(a.program)
        s = harness.summary()
        self.assertIn("total_validated", s)
        self.assertIn("passed", s)
        self.assertGreater(s["total_validated"], 0)

    def test_to_dict(self):
        from bpfstrike.validator.verifier_harness import VerifierHarness
        from bpfstrike.attacks.offensive_programs import generate_syscall_hook
        harness = VerifierHarness()
        result = harness.validate(generate_syscall_hook().program)
        d = result.to_dict()
        self.assertIn("valid", d)
        self.assertIn("stats", d)


class TestV4Exports(unittest.TestCase):
    def test_loader_imports(self):
        from bpfstrike import StealthLoader, LoaderConfig, LoadResult
        self.assertTrue(callable(StealthLoader))

    def test_validator_imports(self):
        from bpfstrike import VerifierHarness, ValidationResult, ValidationIssue
        self.assertTrue(callable(VerifierHarness))

    def test_version(self):
        import bpfstrike
        self.assertEqual(bpfstrike.__version__, "4.0.0")


if __name__ == "__main__":
    unittest.main()
