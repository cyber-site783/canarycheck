#!/usr/bin/env python3
"""CanaryCheck - Your Own Binary Exploit-Mitigation Checker.

Reads a binary's own headers (no external parser, struct only)
and reports which exploit mitigations are switched on:

    ELF: NX, PIE, stack canary, RELRO (full / partial) and fortified
         functions.
    PE:  NX, ASLR, Control Flow Guard (CFG) and SafeSEH.

Usage:
    python3 canarycheck.py <binary> [-o report.txt] [--json]

Exit codes:
    0 - every applicable mitigation is present
    1 - at least one mitigation is missing or partial
    2 - usage error or the file is not a readable ELF or PE binary
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

# --- PE constants ----------------------------------------------------------

PE_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_FILE_DLL = 0x2000

# DllCharacteristics flags (optional header, offset 70, both PE32/PE32+).
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000

PE_MACHINE_NAMES = {IMAGE_FILE_MACHINE_I386: "i386",
                    IMAGE_FILE_MACHINE_AMD64: "x86-64"}

# Verdict values used in the table and the JSON report.
PRESENT = "PRESENT"
PARTIAL = "PARTIAL"
MISSING = "MISSING"
NOT_APPLICABLE = "N/A"


class NotElfError(Exception):
    """Raised when the file is not a readable ELF binary."""


class NotPeError(Exception):
    """Raised when the file is not a readable PE binary."""


class NotBinaryError(Exception):
    """Raised when the file is neither an ELF nor a PE binary."""


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


# --- PE parsing ------------------------------------------------------------

class PeFile:
    """Minimal PE reader: DOS header, PE signature, COFF header and the
    DllCharacteristics field of the optional header. Standard library
    only. PE files are always little-endian."""

    def __init__(self, path):
        with open(path, "rb") as f:
            self.data = f.read()
        self._parse_dos_header()
        self._parse_coff_header()
        self._parse_optional_header()

    def _parse_dos_header(self):
        """Read e_lfanew (offset of the PE signature) from the DOS header."""
        if self.data[:2] != PE_MAGIC:
            raise NotPeError("not a PE file (bad MZ magic bytes)")
        if len(self.data) < 64:
            raise NotPeError("truncated PE file (DOS header incomplete)")
        self.e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.e_lfanew + 6 > len(self.data):
            raise NotPeError("truncated PE file (e_lfanew past end of file)")
        if self.data[self.e_lfanew:self.e_lfanew + 4] != PE_SIGNATURE:
            raise NotPeError("bad PE signature at e_lfanew")

    def _parse_coff_header(self):
        """Read the 20-byte COFF header after the PE signature."""
        off = self.e_lfanew + 4
        size = struct.calcsize("<HHIIIHH")
        if off + size > len(self.data):
            raise NotPeError("truncated COFF header")
        (self.machine, self.num_sections, self.timestamp,
         self.ptr_symtab, self.num_symbols, self.opt_header_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH",
                                                    self.data, off)
        self.machine_name = PE_MACHINE_NAMES.get(
            self.machine, "machine 0x%04x" % self.machine)
        self.is_dll = bool(self.characteristics & IMAGE_FILE_DLL)

    def _parse_optional_header(self):
        """Read the optional-header magic and DllCharacteristics."""
        off = self.e_lfanew + 24
        if self.opt_header_size == 0:
            raise NotPeError("no optional header (not a PE image)")
        if off + 2 > len(self.data):
            raise NotPeError("truncated optional header")
        magic = struct.unpack_from("<H", self.data, off)[0]
        if magic == 0x10B:
            self.is_64bit = False
            self.format_name = "PE32"
        elif magic == 0x20B:
            self.is_64bit = True
            self.format_name = "PE32+"
        else:
            raise NotPeError("unknown optional-header magic: 0x%04x" % magic)
        # DllCharacteristics is a uint16 at optional-header offset 70
        # in both PE32 and PE32+.
        dc_off = off + 70
        if dc_off + 2 > len(self.data):
            raise NotPeError("truncated optional header "
                             "(no DllCharacteristics)")
        self.dll_characteristics = struct.unpack_from("<H", self.data,
                                                      dc_off)[0]
        kind = "DLL" if self.is_dll else "executable"
        self.type_name = "%s %s, %s" % (self.format_name, kind,
                                        self.machine_name)


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


# --- PE mitigation verdicts --------------------------------------------------

def check_pe_nx(pe):
    """NX is on when the NX_COMPAT flag is set in DllCharacteristics."""
    if pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT:
        return (PRESENT, "NX_COMPAT set (DllCharacteristics 0x%04x)"
                % pe.dll_characteristics)
    return (MISSING, "NX_COMPAT not set (DllCharacteristics 0x%04x)"
            % pe.dll_characteristics)


def check_pe_aslr(pe):
    """ASLR is on when the DYNAMIC_BASE flag is set in DllCharacteristics."""
    dc = pe.dll_characteristics
    if dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE:
        if pe.is_64bit and dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA:
            return (PRESENT, "DYNAMIC_BASE + HIGH_ENTROPY_VA set "
                    "(64-bit ASLR, DllCharacteristics 0x%04x)" % dc)
        return (PRESENT, "DYNAMIC_BASE set (ASLR on, "
                "DllCharacteristics 0x%04x)" % dc)
    return (MISSING, "DYNAMIC_BASE not set (fixed load address, "
            "DllCharacteristics 0x%04x)" % dc)


def check_pe_cfg(pe):
    """Control Flow Guard is on when the GUARD_CF flag is set."""
    if pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF:
        return (PRESENT, "GUARD_CF set (Control Flow Guard on, "
                "DllCharacteristics 0x%04x)" % pe.dll_characteristics)
    return (MISSING, "GUARD_CF not set (Control Flow Guard off, "
            "DllCharacteristics 0x%04x)" % pe.dll_characteristics)


def check_pe_safeseh(pe):
    """SafeSEH only applies to 32-bit x86: it is on when the NO_SEH flag
    is not set. On 64-bit, SEH is table-based, so the check is N/A."""
    if pe.machine == IMAGE_FILE_MACHINE_AMD64:
        return (NOT_APPLICABLE,
                "64-bit PE: SEH is table-based, SafeSEH does not apply")
    if pe.machine != IMAGE_FILE_MACHINE_I386:
        return (NOT_APPLICABLE,
                "SafeSEH only applies to 32-bit x86 (%s)"
                % pe.machine_name)
    if pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH:
        return (MISSING, "NO_SEH set (SafeSEH off, "
                "DllCharacteristics 0x%04x)" % pe.dll_characteristics)
    return (PRESENT, "NO_SEH not set (SafeSEH on, "
            "DllCharacteristics 0x%04x)" % pe.dll_characteristics)


def analyse_elf(path):
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


def analyse_pe(path):
    """Parse one PE binary and return the full result dict."""
    pe = PeFile(path)

    nx_verdict, nx_evidence = check_pe_nx(pe)
    aslr_verdict, aslr_evidence = check_pe_aslr(pe)
    cfg_verdict, cfg_evidence = check_pe_cfg(pe)
    seh_verdict, seh_evidence = check_pe_safeseh(pe)

    checks = [
        {"name": "NX", "verdict": nx_verdict, "evidence": nx_evidence},
        {"name": "ASLR", "verdict": aslr_verdict, "evidence": aslr_evidence},
        {"name": "CFG", "verdict": cfg_verdict, "evidence": cfg_evidence},
        {"name": "SafeSEH", "verdict": seh_verdict, "evidence": seh_evidence},
    ]
    # N/A (e.g. SafeSEH on 64-bit) does not count as a failure.
    failed = [c for c in checks
              if c["verdict"] in (MISSING, PARTIAL)]
    return {
        "file": os.path.basename(path),
        "path": path,
        "class": pe.format_name,
        "endianness": "little-endian",
        "type": pe.type_name,
        "checks": checks,
        "fortified_functions": [],
        "all_present": not failed,
    }


def analyse(path):
    """Detect the file type by magic bytes and parse it (ELF or PE)."""
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic == ELF_MAGIC:
        return analyse_elf(path)
    if magic[:2] == PE_MAGIC:
        return analyse_pe(path)
    raise NotBinaryError("not an ELF or PE binary (unknown file type)")


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
                    "fortified functions in an ELF binary, or NX, ASLR, CFG "
                    "and SafeSEH in a PE binary.")
    parser.add_argument("binary",
                        help="path to the ELF or PE binary to check")
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
    except NotPeError as exc:
        print("error: %s is not a PE binary: %s" % (args.binary, exc),
              file=sys.stderr)
        return 2
    except NotBinaryError as exc:
        print("error: %s: %s" % (args.binary, exc), file=sys.stderr)
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
