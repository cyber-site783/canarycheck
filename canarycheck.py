#!/usr/bin/env python3
"""CanaryCheck - Your Own Binary Exploit-Mitigation Checker.

Reads an ELF binary's own headers (no external parser, struct only)
and reports which exploit mitigations are switched on:

    NX, PIE, stack canary, RELRO (full / partial) and fortified functions.

Usage:
    python3 canarycheck.py <binary> [-o report.txt] [--json]

Exit codes:
    0 - every applicable mitigation is present
    1 - at least one mitigation is missing or partial
    2 - usage error or the file is not a readable ELF binary
"""

import argparse
import json
import os
import struct
import sys

# --- ELF constants -------------------------------------------------------

ELF_MAGIC = b"\x7fELF"

ELFCLASS32 = 1
ELFCLASS64 = 2

ELFDATA_LITTLE = 1
ELFDATA_BIG = 2

ET_REL = 1
ET_EXEC = 2
ET_DYN = 3

PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PT_DYNAMIC = 2

PF_X = 0x1  # segment is executable

DT_NULL = 0
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB

DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

SHT_SYMTAB = 2
SHT_DYNSYM = 11

STACK_CHK_SYMBOL = "__stack_chk_fail"
FORTIFY_SUFFIX = "_chk"

ET_NAMES = {ET_REL: "ET_REL (relocatable)",
            ET_EXEC: "ET_EXEC (executable)",
            ET_DYN: "ET_DYN (shared object / PIE)"}

# Verdict values used in the table and the JSON report.
PRESENT = "PRESENT"
PARTIAL = "PARTIAL"
MISSING = "MISSING"
NOT_APPLICABLE = "N/A"


class NotElfError(Exception):
    """Raised when the file is not a readable ELF binary."""


# --- ELF parsing ---------------------------------------------------------

class ElfFile:
    """Minimal ELF reader: header, program headers, dynamic section,
    section headers and symbol names. Standard library only."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse_ident()
        self._parse_header()
        self._parse_program_headers()
        self._parse_sections()

    def _parse_ident(self):
        """Check the magic bytes, read the class and the endianness."""
        if len(self.data) < 16 or self.data[:4] != ELF_MAGIC:
            raise NotElfError("not an ELF file (bad magic bytes)")
        ei_class = self.data[4]
        ei_data = self.data[5]
        if ei_class not in (ELFCLASS32, ELFCLASS64):
            raise NotElfError("unknown ELF class: %d" % ei_class)
        if ei_data not in (ELFDATA_LITTLE, ELFDATA_BIG):
            raise NotElfError("unknown ELF endianness: %d" % ei_data)
        self.is_64bit = ei_class == ELFCLASS64
        self.endian = "<" if ei_data == ELFDATA_LITTLE else ">"
        self.class_name = "ELF64" if self.is_64bit else "ELF32"
        self.endian_name = ("little-endian" if ei_data == ELFDATA_LITTLE
                            else "big-endian")

    def _parse_header(self):
        """Read the ELF header fields after the 16-byte ident."""
        if self.is_64bit:
            fmt = self.endian + "HHIQQQIHHHHHH"
        else:
            fmt = self.endian + "HHIIIIIHHHHHH"
        size = struct.calcsize(fmt)
        if len(self.data) < 16 + size:
            raise NotElfError("truncated ELF header")
        fields = struct.unpack_from(fmt, self.data, 16)
        (self.e_type, self.e_machine, self.e_version, self.e_entry,
         self.e_phoff, self.e_shoff, self.e_flags, self.e_ehsize,
         self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum,
         self.e_shstrndx) = fields
        self.type_name = ET_NAMES.get(self.e_type, "unknown (%d)" % self.e_type)

    def _parse_program_headers(self):
        """Walk the program header table, keep (type, flags) per segment."""
        self.segments = []
        if self.e_phnum == 0:
            return
        if self.is_64bit:
            fmt = self.endian + "IIQQQQQQ"
        else:
            fmt = self.endian + "IIIIIIII"
        size = struct.calcsize(fmt)
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if off + size > len(self.data):
                raise NotElfError("truncated program header table")
            values = struct.unpack_from(fmt, self.data, off)
            if self.is_64bit:
                p_type, p_flags, p_offset = values[0], values[1], values[2]
            else:
                # 32-bit order: type, offset, vaddr, paddr,
                #               filesz, memsz, flags, align
                p_type, p_offset, p_flags = values[0], values[1], values[6]
            self.segments.append({"type": p_type, "flags": p_flags,
                                  "offset": p_offset})

    def _parse_sections(self):
        """Walk the section header table, keep type/offset/size/link."""
        self.sections = []
        if self.e_shnum == 0:
            return
        if self.is_64bit:
            fmt = self.endian + "IIQQQQIIQQ"
        else:
            fmt = self.endian + "IIIIIIIIII"
        size = struct.calcsize(fmt)
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            if off + size > len(self.data):
                raise NotElfError("truncated section header table")
            values = struct.unpack_from(fmt, self.data, off)
            if self.is_64bit:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_align, sh_entsize) = values
            else:
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_align, sh_entsize) = values
            self.sections.append({"type": sh_type, "offset": sh_offset,
                                  "size": sh_size, "link": sh_link,
                                  "entsize": sh_entsize})

    def _read_string(self, strtab, name_offset):
        """Read one NUL-terminated string out of a string table."""
        end = strtab.find(b"\x00", name_offset)
        if end == -1:
            return ""
        return strtab[name_offset:end].decode("utf-8", "replace")

    def _read_strtab(self, section):
        """Return the raw bytes of a string-table section."""
        start = section["offset"]
        end = start + section["size"]
        if end > len(self.data):
            raise NotElfError("truncated string table")
        return self.data[start:end]

    def dynamic_flags(self):
        """Return (bind_now, found) from the PT_DYNAMIC segment."""
        for seg in self.segments:
            if seg["type"] != PT_DYNAMIC:
                continue
            if self.is_64bit:
                fmt = self.endian + "qQ"
            else:
                fmt = self.endian + "iI"
            size = struct.calcsize(fmt)
            off = seg["offset"]
            while off + size <= len(self.data):
                tag, val = struct.unpack_from(fmt, self.data, off)
                if tag == DT_NULL:
                    break
                if tag == DT_FLAGS and val & DF_BIND_NOW:
                    return True, True
                if tag == DT_FLAGS_1 and val & DF_1_NOW:
                    return True, True
                off += size
            return False, True
        return False, False

    def symbol_names(self):
        """Collect every symbol name from SHT_SYMTAB and SHT_DYNSYM."""
        names = []
        for section in self.sections:
            if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            if section["link"] >= len(self.sections):
                continue
            strtab = self._read_strtab(self.sections[section["link"]])
            if self.is_64bit:
                fmt = self.endian + "IIBBHQQ"
            else:
                fmt = self.endian + "IIIBBH"
            size = struct.calcsize(fmt)
            entsize = section["entsize"] or size
            count = section["size"] // entsize
            for i in range(count):
                off = section["offset"] + i * entsize
                if off + size > len(self.data):
                    break
                st_name = struct.unpack_from(fmt, self.data, off)[0]
                if st_name == 0 or st_name >= len(strtab):
                    continue
                names.append(self._read_string(strtab, st_name))
        return names


# --- Mitigation verdicts ---------------------------------------------------

def check_nx(elf):
    """NX is on when a GNU_STACK segment exists and is not executable."""
    for seg in elf.segments:
        if seg["type"] == PT_GNU_STACK:
            if seg["flags"] & PF_X:
                return MISSING, "PT_GNU_STACK is executable (RWE)"
            return PRESENT, "PT_GNU_STACK present, not executable (RW)"
    return MISSING, "no PT_GNU_STACK segment found"


def check_pie(elf):
    """PIE is on when the file type is ET_DYN (a relocatable binary)."""
    if elf.e_type == ET_DYN:
        return PRESENT, "ET_DYN (position-independent executable)"
    if elf.e_type == ET_EXEC:
        return MISSING, "ET_EXEC (fixed load address)"
    return NOT_APPLICABLE, "ET_REL (relocatable object, no load address)"


def check_canary(elf, symbols):
    """Stack canary is on when the __stack_chk_fail symbol exists."""
    if STACK_CHK_SYMBOL in symbols:
        return PRESENT, "symbol %s found" % STACK_CHK_SYMBOL
    return MISSING, "symbol %s not found" % STACK_CHK_SYMBOL


def check_relro(elf, bind_now):
    """Full RELRO = GNU_RELRO segment + bind-now; without bind-now it
    is partial; without the segment it is missing."""
    has_relro = any(seg["type"] == PT_GNU_RELRO for seg in elf.segments)
    if not has_relro:
        return MISSING, "no PT_GNU_RELRO segment found"
    if bind_now:
        return PRESENT, "PT_GNU_RELRO + bind-now (full RELRO)"
    return PARTIAL, "PT_GNU_RELRO present, no bind-now (partial RELRO)"


def check_fortify(symbols):
    """Fortified functions are symbols whose names end in _chk."""
    fortified = sorted({name for name in symbols
                        if name.endswith(FORTIFY_SUFFIX)})
    if fortified:
        return (PRESENT, "%d fortified function(s): %s"
                % (len(fortified), ", ".join(fortified))), fortified
    return (MISSING, "no fortified (_chk) symbols found"), []


def analyse(path):
    """Parse one binary and return the full result dict."""
    elf = ElfFile(path)
    symbols = elf.symbol_names()
    bind_now, _found = elf.dynamic_flags()

    nx_verdict, nx_evidence = check_nx(elf)
    pie_verdict, pie_evidence = check_pie(elf)
    canary_verdict, canary_evidence = check_canary(elf, symbols)
    relro_verdict, relro_evidence = check_relro(elf, bind_now)
    (fortify_verdict, fortify_evidence), fortified = check_fortify(symbols)

    checks = [
        {"name": "NX", "verdict": nx_verdict, "evidence": nx_evidence},
        {"name": "PIE", "verdict": pie_verdict, "evidence": pie_evidence},
        {"name": "Stack Canary", "verdict": canary_verdict,
         "evidence": canary_evidence},
        {"name": "RELRO", "verdict": relro_verdict, "evidence": relro_evidence},
        {"name": "Fortified Functions", "verdict": fortify_verdict,
         "evidence": fortify_evidence},
    ]
    # N/A (e.g. PIE on a relocatable object) does not count as a failure.
    failed = [c for c in checks
              if c["verdict"] in (MISSING, PARTIAL)]
    return {
        "file": os.path.basename(path),
        "path": path,
        "class": elf.class_name,
        "endianness": elf.endian_name,
        "type": elf.type_name,
        "checks": checks,
        "fortified_functions": fortified,
        "all_present": not failed,
    }


# --- Reporting -------------------------------------------------------------

def render_text(result):
    """Render the per-binary verdict table as plain text."""
    lines = []
    lines.append("CanaryCheck report: %s" % result["file"])
    lines.append("Class: %s, %s, Type: %s"
                 % (result["class"], result["endianness"], result["type"]))
    lines.append("")
    lines.append("%-20s %-9s %s" % ("Mitigation", "Verdict", "Evidence"))
    lines.append("-" * 78)
    for check in result["checks"]:
        lines.append("%-20s %-9s %s"
                     % (check["name"], check["verdict"], check["evidence"]))
    lines.append("-" * 78)
    if result["all_present"]:
        lines.append("Result: ALL MITIGATIONS PRESENT")
    else:
        missing = [c["name"] for c in result["checks"]
                   if c["verdict"] in (MISSING, PARTIAL)]
        lines.append("Result: MISSING/PARTIAL: %s" % ", ".join(missing))
    return "\n".join(lines) + "\n"


def render_json(result):
    """Render the same report as JSON (for pipelines)."""
    return json.dumps(result, indent=2) + "\n"


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="CanaryCheck - check NX, PIE, stack canary, RELRO and "
                    "fortified functions in an ELF binary.")
    parser.add_argument("binary", help="path to the ELF binary to check")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="save the report to FILE as well")
    parser.add_argument("--json", action="store_true",
                        help="write the report as JSON instead of text")
    args = parser.parse_args(argv)

    if not os.path.isfile(args.binary):
        print("error: file not found: %s" % args.binary, file=sys.stderr)
        return 2
    try:
        result = analyse(args.binary)
    except NotElfError as exc:
        print("error: %s is not an ELF binary: %s" % (args.binary, exc),
              file=sys.stderr)
        return 2
    except (OSError, struct.error) as exc:
        print("error: could not read %s: %s" % (args.binary, exc),
              file=sys.stderr)
        return 2

    report = render_json(result) if args.json else render_text(result)
    print(report, end="")
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(report)
            print("Report saved to %s" % args.output)
        except OSError as exc:
            print("error: could not write %s: %s" % (args.output, exc),
                  file=sys.stderr)
            return 2
    return 0 if result["all_present"] else 1


if __name__ == "__main__":
    sys.exit(main())
