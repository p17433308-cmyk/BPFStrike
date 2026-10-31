"""
ELF object generator for BPF programs.

Generates minimal ELF .o files that can be loaded by libbpf, bpftool, or
the bpf(2) syscall. The ELF contains:
  - .text section with BPF bytecode
  - .maps section with map definitions
  - license section
  - BTF section stubs
  - Symbol and string tables
"""
import struct
import hashlib
from dataclasses import dataclass, field
from typing import List, Optional, Dict

from .bpf_bytecode import BPFProgram, BPFMapDef


# ELF constants
ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_REL = 1
EM_BPF = 247
SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHF_ALLOC = 0x02
SHF_EXECINSTR = 0x04
STB_GLOBAL = 1
STT_FUNC = 2
STT_OBJECT = 1


@dataclass
class ELFSection:
    name: str = ""
    sh_type: int = SHT_PROGBITS
    sh_flags: int = 0
    data: bytes = b""
    sh_link: int = 0
    sh_info: int = 0
    sh_entsize: int = 0


def generate_bpf_elf(program: BPFProgram) -> bytes:
    """Generate a minimal ELF .o file containing the BPF program."""
    sections: List[ELFSection] = []
    strtab_data = bytearray(b"\x00")
    shstrtab_data = bytearray(b"\x00")

    def add_shstr(name: str) -> int:
        idx = len(shstrtab_data)
        shstrtab_data.extend(name.encode("ascii") + b"\x00")
        return idx

    def add_str(name: str) -> int:
        idx = len(strtab_data)
        strtab_data.extend(name.encode("ascii") + b"\x00")
        return idx

    # Section 0: NULL
    sections.append(ELFSection())

    # Section 1: .text (BPF bytecode)
    text_name_idx = add_shstr(".text")
    bytecode = program.bytecode()
    sections.append(ELFSection(
        name=".text", sh_type=SHT_PROGBITS,
        sh_flags=SHF_ALLOC | SHF_EXECINSTR,
        data=bytecode,
    ))

    # Section 2: maps (if any)
    maps_name_idx = 0
    if program.maps:
        maps_name_idx = add_shstr("maps")
        maps_data = b""
        for m in program.maps:
            maps_data += struct.pack("<IIIII",
                                     m.map_type, m.key_size, m.value_size,
                                     m.max_entries, m.map_flags)
        sections.append(ELFSection(
            name="maps", sh_type=SHT_PROGBITS,
            sh_flags=SHF_ALLOC, data=maps_data,
            sh_entsize=20,
        ))

    # Section 3: license
    license_name_idx = add_shstr("license")
    sections.append(ELFSection(
        name="license", sh_type=SHT_PROGBITS,
        sh_flags=SHF_ALLOC,
        data=program.license.encode("ascii") + b"\x00",
    ))

    # Build symbol table
    prog_name_idx = add_str(program.name or "bpf_prog")
    symtab_data = b"\x00" * 24  # STN_UNDEF
    # Program function symbol
    symtab_data += struct.pack("<IBBHQQ",
                                prog_name_idx,
                                (STB_GLOBAL << 4) | STT_FUNC,
                                0, 1,  # section index = .text
                                0, len(bytecode))

    # Map symbols
    for i, m in enumerate(program.maps):
        map_name_idx = add_str(m.name or f"map_{i}")
        sec_idx = 2 if program.maps else 0
        symtab_data += struct.pack("<IBBHQQ",
                                    map_name_idx,
                                    (STB_GLOBAL << 4) | STT_OBJECT,
                                    0, sec_idx,
                                    i * 20, 20)

    # Section 4: .strtab
    strtab_name_idx = add_shstr(".strtab")
    strtab_section_idx = len(sections)
    sections.append(ELFSection(
        name=".strtab", sh_type=SHT_STRTAB,
        data=bytes(strtab_data),
    ))

    # Section 5: .symtab
    symtab_name_idx = add_shstr(".symtab")
    sections.append(ELFSection(
        name=".symtab", sh_type=SHT_SYMTAB,
        data=symtab_data,
        sh_link=strtab_section_idx,
        sh_info=1,
        sh_entsize=24,
    ))

    # Section 6: .shstrtab
    shstrtab_name_idx = add_shstr(".shstrtab")
    shstrtab_section_idx = len(sections)
    sections.append(ELFSection(
        name=".shstrtab", sh_type=SHT_STRTAB,
        data=bytes(shstrtab_data),
    ))

    # Build ELF
    ehdr_size = 64
    shdr_size = 64
    num_sections = len(sections)

    # Calculate offsets
    offset = ehdr_size
    section_offsets = []
    for sec in sections:
        if sec.data:
            while offset % 8:
                offset += 1
            section_offsets.append(offset)
            offset += len(sec.data)
        else:
            section_offsets.append(0)

    # Section header table
    while offset % 8:
        offset += 1
    shdr_offset = offset

    # Build ELF header
    elf = bytearray()
    elf += ELF_MAGIC
    elf += bytes([ELFCLASS64, ELFDATA2LSB, EV_CURRENT])
    elf += b"\x00" * 9  # padding
    elf += struct.pack("<HHIQQQIHHHHHH",
                        ET_REL, EM_BPF,
                        EV_CURRENT,
                        0,  # entry
                        0,  # phoff
                        shdr_offset,
                        0,  # flags
                        ehdr_size,
                        0, 0,  # phentsize, phnum
                        shdr_size,
                        num_sections,
                        shstrtab_section_idx)

    # Pad to section data
    while len(elf) < ehdr_size:
        elf += b"\x00"

    # Section data
    for i, sec in enumerate(sections):
        if sec.data:
            while len(elf) < section_offsets[i]:
                elf += b"\x00"
            elf += sec.data

    # Section headers
    while len(elf) < shdr_offset:
        elf += b"\x00"

    # Compute name indices in shstrtab
    name_map = {}
    pos = 0
    for name in [b""] + [s.name.encode() for s in sections if s.name]:
        name_map[name.decode() if name else ""] = pos
        pos += len(name) + 1

    for i, sec in enumerate(sections):
        sh_name = name_map.get(sec.name, 0)
        elf += struct.pack("<IIQQQQIIQQ",
                            sh_name,
                            sec.sh_type,
                            sec.sh_flags,
                            0,  # addr
                            section_offsets[i],
                            len(sec.data),
                            sec.sh_link,
                            sec.sh_info,
                            8 if sec.data else 0,
                            sec.sh_entsize)

    return bytes(elf)


def hash_bpf_program(program: BPFProgram) -> str:
    """SHA-256 hash of BPF bytecode for integrity verification."""
    return hashlib.sha256(program.bytecode()).hexdigest()
