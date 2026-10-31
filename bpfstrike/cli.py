"""BPFStrike CLI — eBPF Offensive Security Framework."""
import argparse
import json
import sys
import os

from . import __version__


def cmd_generate(args):
    from .attacks.offensive_programs import ALL_ATTACKS, generate_all_attacks
    from .evasion.security_bypass import EVASION_ATTACKS, generate_all_evasion_attacks
    from .core.elf_generator import generate_bpf_elf, hash_bpf_program

    if args.attack == "all":
        attacks = generate_all_attacks() + generate_all_evasion_attacks()
    elif args.attack in ALL_ATTACKS:
        attacks = [ALL_ATTACKS[args.attack]()]
    elif args.attack in EVASION_ATTACKS:
        attacks = [EVASION_ATTACKS[args.attack]()]
    else:
        print(f"[-] Unknown attack: {args.attack}")
        print(f"    Available: {', '.join(list(ALL_ATTACKS) + list(EVASION_ATTACKS))}")
        return

    print(f"[*] BPFStrike — Generating {len(attacks)} offensive program(s)")
    for atk in attacks:
        prog = atk.program
        bytecode = prog.bytecode()
        print(f"\n{'='*60}")
        print(f"  [{atk.category.upper()}] {atk.name}")
        print(f"{'='*60}")
        print(f"  Type:         {prog.prog_type.name}")
        print(f"  Attach:       {prog.attach_point}")
        print(f"  Instructions: {prog.insn_count()}")
        print(f"  Bytecode:     {len(bytecode)} bytes")
        print(f"  Maps:         {len(prog.maps)}")
        print(f"  Hash:         {hash_bpf_program(prog)[:16]}...")
        print(f"  MITRE:        {atk.mitre_technique}")
        print(f"  Kernel:       >= {atk.kernel_version_min}")
        print(f"  Capabilities: {', '.join(atk.required_capabilities)}")
        c = prog.complexity_estimate()
        print(f"  Complexity:   {c['instructions']} insns, {c['branches']} branches, "
              f"{c['helper_calls']} calls")
        if atk.detection_indicators:
            print(f"\n  Detection Indicators:")
            for ind in atk.detection_indicators:
                print(f"    - {ind}")

        if args.disasm:
            print(f"\n  Disassembly:")
            print(prog.disassemble())

        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            elf_data = generate_bpf_elf(prog)
            elf_path = os.path.join(args.output_dir, f"{prog.name}.o")
            with open(elf_path, "wb") as f:
                f.write(elf_data)
            print(f"\n  [+] ELF saved: {elf_path} ({len(elf_data)} bytes)")

            raw_path = os.path.join(args.output_dir, f"{prog.name}.bin")
            with open(raw_path, "wb") as f:
                f.write(bytecode)
            print(f"  [+] Raw bytecode: {raw_path}")

    if args.json:
        out = [a.to_dict() for a in attacks]
        print(f"\n{json.dumps(out, indent=2)}")


def cmd_recon(args):
    from .recon.bpf_scanner import BPFScanner

    print("[*] BPFStrike Recon — BPF subsystem enumeration")
    scanner = BPFScanner()
    caps = scanner.scan_capabilities()

    print(f"\n{'='*60}")
    print(f"  Kernel BPF Capabilities")
    print(f"{'='*60}")
    print(f"  Kernel:           {caps.kernel_version}")
    print(f"  BPF Enabled:      {caps.bpf_enabled}")
    print(f"  Unprivileged BPF: {caps.unprivileged_bpf}")
    print(f"  JIT Enabled:      {caps.jit_enabled}")
    print(f"  JIT Harden:       {caps.jit_harden}")
    print(f"  BTF Available:    {caps.btf_available}")
    print(f"  Ringbuf:          {caps.ringbuf_available}")
    print(f"  BPF LSM:          {caps.bpf_lsm_available}")
    print(f"  Prog Types:       {len(caps.prog_types)}")
    print(f"  Attack Surface:   {caps.attack_surface_score()}/100")

    if args.bpftool_progs:
        with open(args.bpftool_progs) as f:
            progs = scanner.parse_bpftool_progs(f.read())
        print(f"\n  Loaded Programs:  {len(progs)}")
        for p in progs:
            flag = " [!]" if p.suspicious else ""
            print(f"    [{p.prog_id}] {p.prog_type:20s} {p.name:30s}{flag}")
            for reason in p.suspicion_reasons:
                print(f"         !! {reason}")

    if args.bpftool_maps:
        with open(args.bpftool_maps) as f:
            maps_list = scanner.parse_bpftool_maps(f.read())
        print(f"\n  Loaded Maps:      {len(maps_list)}")
        for m in maps_list:
            print(f"    [{m.map_id}] {m.map_type:20s} {m.name:30s} "
                  f"k={m.key_size} v={m.value_size} max={m.max_entries}")

    detections = scanner.detect_security_tools()
    detected = [d for d in detections if d.detected]
    if detected:
        print(f"\n  Security Tools Detected: {len(detected)}")
        for d in detected:
            print(f"    [{d.tool_name}] confidence={d.confidence:.0%}")
            for ev in d.evidence:
                print(f"      - {ev}")

    if args.json:
        print(f"\n{json.dumps(scanner.result.summary(), indent=2)}")


def cmd_forensics(args):
    from .forensics.bpf_analyzer import BPFForensicAnalyzer
    from .attacks.offensive_programs import generate_all_attacks
    from .evasion.security_bypass import generate_all_evasion_attacks

    print("[*] BPFStrike Forensics — malicious BPF detection")
    analyzer = BPFForensicAnalyzer()

    if args.bytecode_file:
        with open(args.bytecode_file, "rb") as f:
            bytecode = f.read()
        report = analyzer.analyze_bytecode_raw(bytecode, name=args.bytecode_file)
        reports = [report]
    else:
        print("    Analyzing all known attack patterns...")
        all_attacks = generate_all_attacks() + generate_all_evasion_attacks()
        reports = analyzer.batch_analyze([a.program for a in all_attacks])

    for report in reports:
        rd = report.to_dict()
        risk_color = {"critical": "!!!", "high": "!! ", "medium": "!  ", "low": "   "}
        print(f"\n{'='*60}")
        print(f"  {risk_color.get(rd['overall_risk'], '   ')} [{rd['overall_risk'].upper()}] {rd['program_name']}")
        print(f"{'='*60}")
        print(f"  Hash:       {rd['program_hash'][:16]}...")
        print(f"  Indicators: {rd['indicator_count']}")

        for ind in rd["indicators"]:
            print(f"\n    [{ind['severity'].upper()}] {ind['type']}")
            print(f"      {ind['description']}")
            print(f"      Evidence: {ind['evidence']}")
            if ind['mitre_technique']:
                print(f"      MITRE: {ind['mitre_technique']}")

        if rd["helper_usage"]:
            print(f"\n    Helper Functions:")
            for h, count in rd["helper_usage"].items():
                print(f"      {h}: {count}x")

    if args.output:
        with open(args.output, "w") as f:
            json.dump([r.to_dict() for r in reports], f, indent=2)
        print(f"\n[+] Reports saved to {args.output}")


def cmd_verifier(args):
    from .verifier.bypass_patterns import (
        VERIFIER_CVES, generate_all_bypasses, ALL_BYPASSES,
    )
    from .core.elf_generator import hash_bpf_program

    print("[*] BPFStrike Verifier — bypass patterns and CVE database")

    if args.list_cves:
        print(f"\n{'='*60}")
        print(f"  Known BPF Verifier CVEs ({len(VERIFIER_CVES)})")
        print(f"{'='*60}")
        for cve in VERIFIER_CVES:
            print(f"\n  [{cve['severity'].upper()}] {cve['cve']}")
            print(f"    {cve['title']}")
            print(f"    Kernels: {cve['kernel_versions']}")
            print(f"    CVSS: {cve['cvss']}")
            print(f"    {cve['description'][:100]}...")
        return

    if args.pattern == "all":
        bypasses = generate_all_bypasses()
    elif args.pattern in ALL_BYPASSES:
        bypasses = [ALL_BYPASSES[args.pattern]()]
    else:
        print(f"[-] Unknown pattern: {args.pattern}")
        print(f"    Available: {', '.join(ALL_BYPASSES.keys())}")
        return

    for bp in bypasses:
        prog = bp.program
        print(f"\n{'='*60}")
        print(f"  {bp.name}" + (f" ({bp.cve})" if bp.cve else ""))
        print(f"{'='*60}")
        print(f"  Kernels:      {bp.kernel_versions}")
        print(f"  Technique:    {bp.technique}")
        print(f"  Patched:      {bp.patched}")
        print(f"  Instructions: {prog.insn_count()}")
        print(f"  Bytecode:     {len(prog.bytecode())} bytes")
        print(f"  Hash:         {hash_bpf_program(prog)[:16]}...")
        c = prog.complexity_estimate()
        print(f"  Complexity:   {c['estimated_states']} estimated states")
        print(f"\n  {bp.description[:200]}...")

        if args.disasm:
            print(f"\n  Disassembly:")
            print(prog.disassemble())


def cmd_demo(args):
    from .attacks.offensive_programs import generate_all_attacks
    from .evasion.security_bypass import generate_all_evasion_attacks
    from .forensics.bpf_analyzer import BPFForensicAnalyzer
    from .verifier.bypass_patterns import generate_all_bypasses, VERIFIER_CVES
    from .recon.bpf_scanner import BPFScanner
    from .core.elf_generator import generate_bpf_elf, hash_bpf_program

    print(f"""
{'='*60}
  ____  ____  _____ ____  _        _ _
 | __ )|  _ \\|  ___/ ___|| |_ _ __(_) | _____
 |  _ \\| |_) | |_  \\___ \\| __| '__| | |/ / _ \\
 | |_) |  __/|  _|  ___) | |_| |  | |   <  __/
 |____/|_|   |_|   |____/ \\__|_|  |_|_|\\_\\___|

 eBPF Offensive Security Framework v{__version__}
{'='*60}
""")

    print("[Phase 1] BPF SUBSYSTEM RECONNAISSANCE")
    print("-" * 40)
    scanner = BPFScanner()
    caps = scanner.scan_capabilities()
    print(f"  Kernel:            {caps.kernel_version}")
    print(f"  BPF Enabled:       {caps.bpf_enabled}")
    print(f"  Attack Surface:    {caps.attack_surface_score()}/100")
    print(f"  Prog Types:        {len(caps.prog_types)}")

    print(f"\n[Phase 2] OFFENSIVE PROGRAM GENERATION")
    print("-" * 40)
    attacks = generate_all_attacks()
    evasions = generate_all_evasion_attacks()
    all_programs = attacks + evasions
    total_bytecode = 0
    total_insns = 0
    for atk in all_programs:
        prog = atk.program
        bc = prog.bytecode()
        total_bytecode += len(bc)
        total_insns += prog.insn_count()
        print(f"  [{atk.category:20s}] {atk.name:35s} "
              f"{prog.insn_count():4d} insns  {len(bc):5d} bytes")
    print(f"\n  Total: {len(all_programs)} programs, "
          f"{total_insns} instructions, {total_bytecode} bytes bytecode")

    print(f"\n[Phase 3] ELF OBJECT GENERATION")
    print("-" * 40)
    for atk in all_programs:
        elf = generate_bpf_elf(atk.program)
        h = hash_bpf_program(atk.program)
        print(f"  {atk.program.name:35s} ELF={len(elf):6d}B  SHA256={h[:12]}...")

    print(f"\n[Phase 4] FORENSIC ANALYSIS OF ATTACK PROGRAMS")
    print("-" * 40)
    analyzer = BPFForensicAnalyzer()
    reports = analyzer.batch_analyze([a.program for a in all_programs])
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in reports:
        risk_counts[r.overall_risk] = risk_counts.get(r.overall_risk, 0) + 1
        print(f"  [{r.overall_risk.upper():8s}] {r.program_name:35s} "
              f"{len(r.indicators)} indicators")
    print(f"\n  Risk Summary: {risk_counts}")

    print(f"\n[Phase 5] VERIFIER BYPASS PATTERNS")
    print("-" * 40)
    bypasses = generate_all_bypasses()
    for bp in bypasses:
        c = bp.program.complexity_estimate()
        print(f"  {bp.name:35s} {bp.program.insn_count():4d} insns  "
              f"states={c['estimated_states']}")
    print(f"  Known CVEs: {len(VERIFIER_CVES)}")

    print(f"\n{'='*60}")
    print(f"  BPFStrike Demo Complete")
    print(f"  {len(all_programs)} attacks | {len(bypasses)} verifier bypasses | "
          f"{len(VERIFIER_CVES)} CVEs")
    print(f"  {total_bytecode} bytes of real BPF bytecode generated")
    print(f"{'='*60}")


def cmd_compose(args):
    from .composer.rootkit_builder import RootkitComposer
    import json as _json

    composer = RootkitComposer()

    if args.list_presets:
        print("[*] BPFStrike Rootkit Composer — Presets")
        for name, cfg in composer.list_presets().items():
            modules = [k for k, v in cfg["modules_enabled"].items() if v]
            print(f"\n  [{name}] {cfg['name']}")
            print(f"    Modules: {', '.join(modules)}")
        return

    print(f"[*] BPFStrike Rootkit Composer — Building '{args.preset}' rootkit")
    rootkit = composer.compose_preset(args.preset)

    print(f"\n{'='*60}")
    print(f"  Composed Rootkit: {rootkit.config.name}")
    print(f"{'='*60}")
    print(f"  Components:    {rootkit.component_count()}")
    print(f"  Instructions:  {rootkit.total_instructions()}")
    print(f"  Bytecode:      {rootkit.total_bytecode()} bytes")
    print(f"  Shared Maps:   {len(rootkit.shared_maps)}")
    print(f"  Rootkit Hash:  {rootkit.rootkit_hash[:16]}...")

    if rootkit.dispatcher:
        d = rootkit.dispatcher
        print(f"\n  [DISPATCHER] {d.name}")
        print(f"    Attach: {d.attach_point}")
        print(f"    Insns:  {d.insn_count()}")

    for comp in rootkit.components:
        print(f"\n  [{comp.role.upper()}] {comp.name}")
        print(f"    Attach:     {comp.attach_point}")
        print(f"    Tail Index: {comp.tail_call_index}")
        print(f"    Insns:      {comp.program.insn_count()}")
        print(f"    {comp.description[:80]}...")

    print(f"\n  Shared Maps:")
    for m in rootkit.shared_maps:
        print(f"    {m.name:20s} type={m.map_type.name:20s} "
              f"k={m.key_size} v={m.value_size} max={m.max_entries}")

    if args.output_dir:
        import os
        os.makedirs(args.output_dir, exist_ok=True)
        elfs = rootkit.generate_elfs()
        for fname, data in elfs.items():
            path = os.path.join(args.output_dir, fname)
            with open(path, "wb") as f:
                f.write(data)
            print(f"\n  [+] {fname}: {len(data)} bytes")

    if args.json:
        print(f"\n{_json.dumps(rootkit.to_dict(), indent=2)}")


def cmd_detect(args):
    from .detection.rule_generator import DetectionRuleGenerator
    import os

    print("[*] BPFStrike Detection Rule Generator")
    gen = DetectionRuleGenerator()

    if args.format == "all":
        rulesets = gen.generate_all()
    else:
        rs = gen.generate_format(args.format)
        if rs is None:
            print(f"[-] Unknown format: {args.format}")
            print(f"    Available: {', '.join(gen.FORMATS)}")
            return
        rulesets = {args.format: rs}

    for fmt, rs in rulesets.items():
        print(f"\n{'='*60}")
        print(f"  {fmt.upper()} Rules — {len(rs.rules)} rules")
        print(f"{'='*60}")
        for rule in rs.rules:
            print(f"  [{rule.severity.upper():8s}] {rule.rule_id}: {rule.name}")
            if rule.mitre_technique:
                print(f"             MITRE: {rule.mitre_technique}")

    total = gen.total_rules()
    print(f"\n  Total: {total} detection rules across "
          f"{len(rulesets)} format(s)")

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        ext_map = {"yara": ".yar", "sigma": ".yml", "falco": ".yaml",
                   "snort": ".rules"}
        for fmt, rs in rulesets.items():
            ext = ext_map.get(fmt, ".txt")
            path = os.path.join(args.output_dir, f"bpfstrike_rules{ext}")
            with open(path, "w") as f:
                f.write(rs.export())
            print(f"  [+] {path}")


def cmd_obfuscate(args):
    from .obfuscator.bytecode_obfuscator import BytecodeObfuscator
    from .attacks.offensive_programs import ALL_ATTACKS, generate_all_attacks
    from .evasion.security_bypass import EVASION_ATTACKS, generate_all_evasion_attacks

    print(f"[*] BPFStrike Bytecode Obfuscator — preset={args.preset}")
    obfuscator = BytecodeObfuscator()

    if args.attack == "all":
        attacks = generate_all_attacks() + generate_all_evasion_attacks()
    elif args.attack in ALL_ATTACKS:
        attacks = [ALL_ATTACKS[args.attack]()]
    elif args.attack in EVASION_ATTACKS:
        attacks = [EVASION_ATTACKS[args.attack]()]
    else:
        print(f"[-] Unknown attack: {args.attack}")
        return

    for atk in attacks:
        result = obfuscator.obfuscate(atk.program, preset=args.preset)

        print(f"\n{'='*60}")
        print(f"  {atk.name}")
        print(f"{'='*60}")
        print(f"  Original:    {result.original_insn_count} insns, "
              f"{result.original_bytecode_size} bytes")
        print(f"  Obfuscated:  {result.obfuscated_insn_count} insns, "
              f"{result.obfuscated_bytecode_size} bytes")
        print(f"  Bloat:       {result.bloat_ratio():.2f}x")
        print(f"  Entropy:     {result.entropy_before:.4f} → "
              f"{result.entropy_after:.4f}")
        print(f"  Hash Before: {result.original_hash[:16]}...")
        print(f"  Hash After:  {result.obfuscated_hash[:16]}...")
        print(f"  Techniques:  {', '.join(result.techniques_applied)}")

        if args.evasion_test:
            evasion = obfuscator.evasion_test(atk.program, preset=args.preset)
            print(f"\n  Evasion Test:")
            print(f"    Indicators Before: {evasion.indicators_before}")
            print(f"    Indicators After:  {evasion.indicators_after}")
            print(f"    Bypass Rate:       {evasion.bypass_rate:.0%}")
            for detail in evasion.details:
                print(f"      {detail}")


def cmd_compile(args):
    from .compiler.payload_compiler import PayloadCompiler
    import os

    compiler = PayloadCompiler()

    if args.list_modules:
        print("[*] BPFStrike Payload Compiler — Module Types")
        for name, info in compiler.list_module_types().items():
            print(f"\n  [{name}]")
            print(f"    {info['description']}")
            print(f"    Prog:   {info['prog_type']}")
            print(f"    Attach: {info['attach']}")
            print(f"    MITRE:  {info['mitre']}")
        return

    if args.list_examples:
        print("[*] BPFStrike Payload Compiler — Example Specs")
        for name, info in compiler.list_examples().items():
            print(f"  [{name}] {info['description']}")
            print(f"    Modules: {', '.join(info['modules'])}")
        return

    if args.example:
        result = compiler.compile_example(args.example)
    elif args.spec_file:
        with open(args.spec_file) as f:
            result = compiler.compile_yaml_string(f.read())
    else:
        result = compiler.compile_example("stealth_rootkit")

    if result.errors:
        for err in result.errors:
            print(f"[-] {err}")
        return

    print(f"\n{'='*60}")
    print(f"  Compiled Payload: {result.name}")
    print(f"{'='*60}")
    print(f"  Modules:       {len(result.modules)}")
    print(f"  Instructions:  {result.total_instructions()}")
    print(f"  Bytecode:      {result.total_bytecode()} bytes")
    print(f"  Shared Maps:   {len(result.shared_maps)}")
    print(f"  Payload Hash:  {result.payload_hash[:16]}...")
    print(f"  Capabilities:  {', '.join(sorted(result.required_capabilities()))}")
    print(f"  MITRE:         {', '.join(sorted(result.mitre_techniques()))}")

    for mod in result.modules:
        d = mod.to_dict()
        print(f"\n  [{d['type'].upper()}] {d['prog_type']} @ {d['attach_point']}")
        print(f"    Instructions: {d['instructions']}")
        print(f"    Bytecode:     {d['bytecode_size']} bytes")

    for w in result.warnings:
        print(f"\n  [!] {w}")

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        elfs = result.generate_elfs()
        for fname, data in elfs.items():
            path = os.path.join(args.output_dir, fname)
            with open(path, "wb") as f:
                f.write(data)
            print(f"\n  [+] {fname}: {len(data)} bytes")

    if args.json:
        print(f"\n{json.dumps(result.to_dict(), indent=2)}")


def cmd_antiforensics(args):
    from .antiforensics.countermeasures import AntiForensicEngine
    import os

    engine = AntiForensicEngine()

    if args.list_countermeasures:
        print("[*] BPFStrike Anti-Forensics — Countermeasures")
        for name, info in engine.list_countermeasures().items():
            print(f"\n  [{name}]")
            print(f"    Category: {info['category']}")
            print(f"    {info['description']}")
            print(f"    MITRE: {info['mitre']}")
        return

    if args.list_presets:
        print("[*] BPFStrike Anti-Forensics — Presets")
        for name, modules in engine.list_presets().items():
            print(f"  [{name}] {', '.join(modules)}")
        return

    suite = engine.generate_suite(preset=args.preset)

    print(f"\n{'='*60}")
    print(f"  Anti-Forensic Suite — preset={args.preset}")
    print(f"{'='*60}")
    print(f"  Programs:     {len(suite.programs)}")
    print(f"  Instructions: {suite.total_instructions()}")
    print(f"  Bytecode:     {suite.total_bytecode()} bytes")
    print(f"  Suite Hash:   {suite.suite_hash[:16]}...")

    for p in suite.programs:
        d = p.to_dict()
        print(f"\n  [{d['category'].upper()}] {d['name']}")
        print(f"    {d['description']}")
        print(f"    Trigger: {d['trigger']}")
        print(f"    MITRE:   {d['mitre']}")
        print(f"    Insns:   {d['instructions']}, {d['bytecode_size']} bytes")

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)
        elfs = suite.generate_elfs()
        for fname, data in elfs.items():
            path = os.path.join(args.output_dir, fname)
            with open(path, "wb") as f:
                f.write(data)
            print(f"\n  [+] {fname}: {len(data)} bytes")

    if args.json:
        print(f"\n{json.dumps(suite.to_dict(), indent=2)}")


def cmd_chain(args):
    from .chainer.exploit_chain import ExploitChainer

    chainer = ExploitChainer()

    if args.list_cves:
        print("[*] BPFStrike Exploit Chainer — CVE Database")
        for cve_id, info in chainer.list_cves().items():
            print(f"\n  [{cve_id}]")
            print(f"    {info['description']}")
            print(f"    Kernels:     {info['affected_range']}")
            print(f"    Subsystem:   {info['subsystem']}")
            print(f"    Reliability: {info['reliability']}")
        return

    print(f"[*] BPFStrike Exploit Chainer — kernel={args.kernel}, "
          f"rootkit={args.rootkit_preset}")
    result = chainer.execute_chain(
        version_string=args.kernel,
        rootkit_preset=args.rootkit_preset,
    )

    print(f"\n{'='*60}")
    print(f"  Exploit Chain Results")
    print(f"{'='*60}")

    for stage in result.stages:
        status_icon = "[+]" if stage.status == "completed" else "[-]"
        print(f"\n  {status_icon} Stage: {stage.stage}")
        print(f"      Status:   {stage.status}")
        print(f"      Duration: {stage.duration_ms:.2f}ms")
        if stage.error:
            print(f"      Error:    {stage.error}")

    print(f"\n  Chain Success: {result.success()}")
    print(f"  Chain Hash:    {result.chain_hash[:16]}...")
    print(f"  Total Time:    {result.total_duration_ms:.2f}ms")
    if result.selected_cve:
        print(f"  Selected CVE:  {result.selected_cve.cve_id}")
    if result.bypass_program:
        print(f"  Bypass Insns:  {result.bypass_program.insn_count()}")
    if result.rootkit:
        print(f"  Rootkit Parts: {len(result.rootkit.components)}")

    if args.json:
        print(f"\n{json.dumps(result.to_dict(), indent=2)}")


def cmd_load(args):
    from .loader.stealth_loader import StealthLoader, LoaderConfig
    from .attacks.offensive_programs import ALL_ATTACKS, generate_all_attacks

    print(f"[*] BPFStrike Stealth Loader — method={args.method}")

    if args.list_methods:
        loader = StealthLoader()
        for name, desc in loader.list_methods().items():
            print(f"  [{name}] {desc}")
        return

    if args.list_shellcode:
        loader = StealthLoader()
        for method in ["bpf_syscall", "memfd_create"]:
            sc = loader.get_injection_shellcode(method)
            print(f"\n  [{method}]")
            print(f"    {sc.get('description', '')}")
            print(f"    Size: {sc.get('shellcode_size', 0)} bytes")
            print(f"    Hex:  {sc.get('shellcode_hex', '')[:64]}...")
        return

    config = LoaderConfig(
        method=args.method,
        name_spoof=args.name_spoof or "",
        target_pid=args.target_pid or 0,
    )
    loader = StealthLoader(config)

    if args.attack == "all":
        attacks = generate_all_attacks()
    elif args.attack in ALL_ATTACKS:
        attacks = [ALL_ATTACKS[args.attack]()]
    else:
        print(f"[-] Unknown attack: {args.attack}")
        return

    for atk in attacks:
        result = loader.prepare_load(atk.program)
        print(f"\n{'='*60}")
        print(f"  {atk.name} — {config.method} loader")
        print(f"{'='*60}")
        print(f"  Success:     {result.success}")
        print(f"  Method:      {result.method}")
        print(f"  Bytecode:    {result.bytecode_size} bytes")
        print(f"  Maps:        {len(result.map_fds)}")
        print(f"  Syscalls:    {len(result.syscall_sequence)}")
        print(f"  Cleanup:     {len(result.cleanup_actions)} actions")
        if result.error:
            print(f"  Error:       {result.error}")

        if args.verbose:
            print(f"\n  Syscall Sequence:")
            for i, sc in enumerate(result.syscall_sequence):
                print(f"    [{i}] {sc['syscall']}({sc.get('cmd', '')})")
            print(f"\n  Cleanup Actions:")
            for action in result.cleanup_actions:
                print(f"    - {action}")

    if args.json:
        out = [loader.prepare_load(a.program).to_dict() for a in attacks]
        print(f"\n{json.dumps(out, indent=2)}")


def cmd_validate(args):
    from .validator.verifier_harness import VerifierHarness
    from .attacks.offensive_programs import generate_all_attacks
    from .evasion.security_bypass import generate_all_evasion_attacks
    from .verifier.bypass_patterns import generate_all_bypasses

    print("[*] BPFStrike Verifier Harness — structural validation")
    harness = VerifierHarness()

    all_attacks = generate_all_attacks()
    evasions = generate_all_evasion_attacks()
    bypasses = generate_all_bypasses()

    all_progs = ([a.program for a in all_attacks] +
                 [a.program for a in evasions] +
                 [b.program for b in bypasses])

    results = harness.validate_batch(all_progs)

    for r in results:
        status = "[PASS]" if r.valid else "[FAIL]"
        err_count = r.error_count()
        warn_count = r.warning_count()
        print(f"  {status} {r.program_name:40s} "
              f"insns={r.stats.get('instructions', 0):4d} "
              f"stack={r.stats.get('stack_depth', 0):3d} "
              f"err={err_count} warn={warn_count}")

        if args.verbose and r.issues:
            for issue in r.issues:
                prefix = "!!" if issue.severity == "error" else "  "
                loc = f"@{issue.instruction}" if issue.instruction >= 0 else ""
                print(f"      {prefix} [{issue.category}]{loc} {issue.message}")

    summary = harness.summary()
    print(f"\n  Summary: {summary['passed']}/{summary['total_validated']} passed, "
          f"{summary['total_errors']} errors, {summary['total_warnings']} warnings")

    if args.json:
        print(f"\n{json.dumps(summary, indent=2)}")


def main():
    parser = argparse.ArgumentParser(
        prog="bpfstrike",
        description="BPFStrike — eBPF Offensive Security Framework",
    )
    parser.add_argument("--version", action="version",
                        version=f"BPFStrike {__version__}")
    sub = parser.add_subparsers(dest="command", help="Available commands")

    p = sub.add_parser("generate", help="Generate offensive BPF programs")
    p.add_argument("attack", nargs="?", default="all",
                   help="Attack name or 'all'")
    p.add_argument("--disasm", action="store_true", help="Show disassembly")
    p.add_argument("--output-dir", "-o", help="Save ELF and raw bytecode")
    p.add_argument("--json", action="store_true", help="JSON output")

    p = sub.add_parser("recon", help="BPF subsystem reconnaissance")
    p.add_argument("--bpftool-progs",
                   help="bpftool prog list --json output file")
    p.add_argument("--bpftool-maps",
                   help="bpftool map list --json output file")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("forensics", help="Detect malicious BPF programs")
    p.add_argument("--bytecode-file", help="Raw BPF bytecode to analyze")
    p.add_argument("--output", "-o", help="Save report to JSON")

    p = sub.add_parser("verifier", help="Verifier bypass patterns and CVEs")
    p.add_argument("pattern", nargs="?", default="all",
                   help="Bypass pattern name or 'all'")
    p.add_argument("--list-cves", action="store_true",
                   help="List known verifier CVEs")
    p.add_argument("--disasm", action="store_true", help="Show disassembly")

    sub.add_parser("demo", help="Full demonstration")

    # compose
    p = sub.add_parser("compose", help="Compose a coordinated rootkit")
    p.add_argument("preset", nargs="?", default="full",
                   help="Preset: stealth, full, recon, minimal")
    p.add_argument("--list-presets", action="store_true")
    p.add_argument("--output-dir", "-o", help="Save ELF objects")
    p.add_argument("--json", action="store_true")

    # detect
    p = sub.add_parser("detect", help="Generate detection rules")
    p.add_argument("format", nargs="?", default="all",
                   help="Rule format: yara, sigma, falco, snort, or all")
    p.add_argument("--output-dir", "-o", help="Save rule files")

    # obfuscate
    p = sub.add_parser("obfuscate", help="Obfuscate BPF bytecode")
    p.add_argument("attack", nargs="?", default="all",
                   help="Attack to obfuscate or 'all'")
    p.add_argument("--preset", default="medium",
                   help="Preset: light, medium, heavy, maximum")
    p.add_argument("--evasion-test", action="store_true",
                   help="Test obfuscation against forensic analyzer")

    # compile
    p = sub.add_parser("compile", help="Compile YAML/JSON payload spec to BPF bytecode")
    p.add_argument("--spec-file", "-f", help="JSON payload specification file")
    p.add_argument("--example", "-e", help="Built-in example name")
    p.add_argument("--list-modules", action="store_true")
    p.add_argument("--list-examples", action="store_true")
    p.add_argument("--output-dir", "-o", help="Save ELF objects")
    p.add_argument("--json", action="store_true")

    # antiforensics
    p = sub.add_parser("antiforensics", help="Anti-forensic countermeasures")
    p.add_argument("--preset", default="paranoid",
                   help="Preset: paranoid, stealth, delayed, minimal")
    p.add_argument("--list-countermeasures", action="store_true")
    p.add_argument("--list-presets", action="store_true")
    p.add_argument("--output-dir", "-o", help="Save ELF objects")
    p.add_argument("--json", action="store_true")

    # chain
    p = sub.add_parser("chain", help="Automated exploit chain pipeline")
    p.add_argument("kernel", nargs="?", default="5.10.0",
                   help="Target kernel version")
    p.add_argument("--rootkit-preset", default="stealth",
                   help="Rootkit preset for deployment stage")
    p.add_argument("--list-cves", action="store_true")
    p.add_argument("--json", action="store_true")

    # load
    p = sub.add_parser("load", help="Stealth BPF loader (syscall sequences)")
    p.add_argument("attack", nargs="?", default="all",
                   help="Attack to prepare for loading")
    p.add_argument("--method", default="direct",
                   help="Loading method: direct, memfd, ptrace, procmem")
    p.add_argument("--name-spoof", help="Fake program name in kernel")
    p.add_argument("--target-pid", type=int, help="Target PID for injection")
    p.add_argument("--list-methods", action="store_true")
    p.add_argument("--list-shellcode", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--json", action="store_true")

    # validate
    p = sub.add_parser("validate", help="Validate BPF bytecode structure")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Show all validation issues")
    p.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "generate": cmd_generate, "recon": cmd_recon,
        "forensics": cmd_forensics, "verifier": cmd_verifier,
        "demo": cmd_demo, "compose": cmd_compose,
        "detect": cmd_detect, "obfuscate": cmd_obfuscate,
        "compile": cmd_compile, "antiforensics": cmd_antiforensics,
        "chain": cmd_chain, "load": cmd_load,
        "validate": cmd_validate,
    }
    commands[args.command](args)


if __name__ == "__main__":
    main()
