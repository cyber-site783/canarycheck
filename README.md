# CanaryCheck — Your Own Binary Exploit-Mitigation Checker

CanaryCheck is a command-line tool that reads an ELF or PE binary's own
headers and reports which exploit mitigations are switched on. For ELF
binaries: **NX, PIE, stack canary, RELRO and fortified functions**. For
Windows PE binaries (`.exe` / `.dll`): **NX, ASLR, Control Flow Guard
(CFG) and SafeSEH**.

It parses the ELF header, program headers, section headers, symbol table
and dynamic section by hand with Python's `struct` module — **no external
parser, no dependencies**. Before anyone analyses a binary, they ask what
protections it has. CanaryCheck answers that question from the bytes
themselves.

## The five mitigations

| Mitigation | How CanaryCheck detects it |
|---|---|
| **NX** (No-eXecute) | The `PT_GNU_STACK` program header exists and is **not** executable. If the stack segment is executable (`RWE`), code on the stack can run — NX is missing. |
| **PIE** (Position-Independent Executable) | The ELF file type is `ET_DYN` (a position-independent executable). `ET_EXEC` means a fixed load address — PIE is missing. `ET_REL` (relocatable object) is reported as N/A. |
| **Stack Canary** | The `__stack_chk_fail` symbol exists in the symbol table. The compiler adds it when stack protection is enabled, so the binary aborts instead of returning into smashed stack data. |
| **RELRO** (RELocation Read-Only) | **Full** = a `PT_GNU_RELRO` segment **plus** the bind-now flag (`DF_BIND_NOW` / `DF_1_NOW` in the dynamic section). **Partial** = the segment without bind-now. **Missing** = no `PT_GNU_RELRO` segment at all. |
| **Fortified Functions** | Symbols whose names end in `_chk` (for example `__strcpy_chk`). The compiler emits these checked versions when `_FORTIFY_SOURCE` is on and it can see the destination buffer size. |

## Windows PE binaries

CanaryCheck detects the file type from its magic bytes: `MZ` means PE,
`\x7fELF` means ELF. A PE file is parsed the same way — by hand with
Python's `struct` module — reading the DOS header (`e_lfanew`), the PE
signature, the COFF header and the `DllCharacteristics` field of the
optional header (offset 70 in both PE32 and PE32+).

| Mitigation | How CanaryCheck detects it |
|---|---|
| **NX** (No-eXecute) | The `NX_COMPAT` flag (`0x0100`) is set in `DllCharacteristics`. Without it, data pages can be marked executable. |
| **ASLR** (Address Space Layout Randomization) | The `DYNAMIC_BASE` flag (`0x0040`) is set in `DllCharacteristics`, so the image can load at a random address. On 64-bit, `HIGH_ENTROPY_VA` (`0x0020`) is reported too when it is set. |
| **CFG** (Control Flow Guard) | The `GUARD_CF` flag (`0x4000`) is set in `DllCharacteristics`. The compiler inserts CFG checks that stop indirect calls from jumping to an unexpected target. |
| **SafeSEH** | Only meaningful on 32-bit x86: it is on when the `NO_SEH` flag (`0x0400`) is **not** set. On 64-bit, SEH is table-based, so the check is reported as N/A. |

The report header says whether the file is PE32 or PE32+, the machine
(`i386` or `x86-64`) and whether it is an executable or a DLL.

### Running on Windows

Install Python 3 on Windows, then run the tool on a local `.exe` file:

```cmd
python canarycheck.py program.exe
```

CanaryCheck only reads the file you give it — it does not scan, connect
to, or target a live machine. Point it at `.exe` files you compiled
yourself.

### Building test .exe files (MinGW)

On Linux, install the MinGW cross-compilers and build the same test
program for Windows:

```bash
sudo apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686

# 64-bit, NX + ASLR on
x86_64-w64-mingw32-gcc -O2 test_program.c -o test64.exe \
    -Wl,--dynamicbase,--nxcompat -Wl,--high-entropy-va

# One mitigation off at a time
x86_64-w64-mingw32-gcc -O2 test_program.c -o test64_no_nx.exe \
    -Wl,--dynamicbase -Wl,--high-entropy-va
x86_64-w64-mingw32-gcc -O2 test_program.c -o test64_no_aslr.exe \
    -Wl,--nxcompat

# 32-bit (SafeSEH applies here)
i686-w64-mingw32-gcc -O2 test_program.c -o test32.exe \
    -Wl,--dynamicbase,--nxcompat
i686-w64-mingw32-gcc -O2 test_program.c -o test32_no_safeseh.exe \
    -Wl,--dynamicbase,--nxcompat,--no-seh
```

Then check each one — for example `python3 canarycheck.py test64.exe`
should report NX and ASLR PRESENT, with SafeSEH as N/A (and CFG MISSING,
see below).

**Control Flow Guard needs a compiler that supports it.** GCC's MinGW
linker cannot set the `GUARD_CF` flag — there is no CFGuard support in GCC
or Binutils. Build the CFG test binary with Clang (llvm-mingw) instead:

```bash
clang --target=x86_64-pc-windows-gnu -mguard=cf -O2 test_program.c \
    -o test64_cfg.exe
```

or with MSVC on Windows (`/guard:cf`). Then
`python3 canarycheck.py test64_cfg.exe` should report CFG PRESENT.

## Requirements

- **Python 3** (3.8 or newer). Nothing else — standard library only.
- **gcc** is only needed to build the test binaries in `examples/`.
- **MinGW** (`gcc-mingw-w64`) is only needed to build test `.exe` files.

## Installation

```bash
git clone https://github.com/cyber-site783/canarycheck.git
cd canarycheck
```

No installation step and no `pip install` — run it directly:

```bash
python3 canarycheck.py <binary>
```

## Usage

```bash
# Check one binary, print the verdict table
python3 canarycheck.py /path/to/binary

# Also save the report to a file
python3 canarycheck.py /path/to/binary -o report.txt

# JSON report instead of the text table (for pipelines)
python3 canarycheck.py /path/to/binary --json
python3 canarycheck.py /path/to/binary --json -o report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every applicable mitigation is present |
| `1` | At least one mitigation is missing or partial |
| `2` | Usage error, or the file is not a readable ELF or PE binary |

## Sample output

Real output from the test binary `examples/test_program.c`, compiled with
all mitigations on (see "Building the test binaries" below):

```
CanaryCheck report: secure
Class: ELF64, little-endian, Type: ET_DYN (shared object / PIE)

Mitigation           Verdict   Evidence
------------------------------------------------------------------------------
NX                   PRESENT   PT_GNU_STACK present, not executable (RW)
PIE                  PRESENT   ET_DYN (position-independent executable)
Stack Canary         PRESENT   symbol __stack_chk_fail found
RELRO                PRESENT   PT_GNU_RELRO + bind-now (full RELRO)
Fortified Functions  PRESENT   3 fortified function(s): __memcpy_chk, __stpcpy_chk, __strcpy_chk
------------------------------------------------------------------------------
Result: ALL MITIGATIONS PRESENT
```

The same report is saved in [`examples/sample-report.txt`](examples/sample-report.txt).

A binary compiled without one mitigation fails the check, for example
without a stack canary:

```
Stack Canary         MISSING   symbol __stack_chk_fail not found
------------------------------------------------------------------------------
Result: MISSING/PARTIAL: Stack Canary
```

## Building the test binaries

Only binaries you compile yourself are used for testing — never point the
tool at system binaries or software you do not own. `examples/test_program.c`
uses `strcpy` / `strcat`, so fortification and the stack canary apply to it.

```bash
cd examples

# All mitigations on
gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -Wl,-z,relro,-z,now -z noexecstack -o secure test_program.c

# One mitigation off at a time
gcc -O2 -fno-stack-protector -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -Wl,-z,relro,-z,now -z noexecstack -o no-canary test_program.c
gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-pie -no-pie \
    -Wl,-z,relro,-z,now -z noexecstack -o no-pie test_program.c
gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -Wl,-z,relro,-z,lazy -z noexecstack -o partial-relro test_program.c
gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -Wl,-z,norelro -z noexecstack -o no-relro test_program.c
gcc -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -pie -fPIE \
    -Wl,-z,relro,-z,now -z execstack -o nx-off test_program.c
gcc -O0 -U_FORTIFY_SOURCE -fstack-protector-all -pie -fPIE \
    -Wl,-z,relro,-z,now -z noexecstack -o no-fortify test_program.c
```

Then check each one:

```bash
cd ..
python3 canarycheck.py examples/secure       # exit 0, all present
python3 canarycheck.py examples/no-canary    # exit 1, Stack Canary MISSING
python3 canarycheck.py examples/no-pie       # exit 1, PIE MISSING
python3 canarycheck.py examples/partial-relro # exit 1, RELRO PARTIAL
python3 canarycheck.py examples/no-relro     # exit 1, RELRO MISSING
python3 canarycheck.py examples/nx-off       # exit 1, NX MISSING
python3 canarycheck.py examples/no-fortify   # exit 1, Fortified Functions MISSING
```

### Test results (verified on this machine)

Every verdict matched the flags the binary was compiled with, and the
program-header listing was checked against `readelf -l` on the same binary
(13 segments, identical types and flags). A plain text file is rejected
cleanly with exit code 2. 32-bit and big-endian ELF files are parsed too
(32-bit verified with a `as --32` object file; big-endian verified with a
hand-built ELF64 file).

One toolchain note, worth knowing when you reproduce the matrix: on Ubuntu,
gcc adds bind-now by default, so `-Wl,-z,relro` alone still produces full
RELRO. Use `-Wl,-z,lazy` explicitly to get a genuinely partial-RELRO binary.

PE files were tested the same way: eight test binaries covering PE32 and
PE32+, EXE and DLL, each of NX / ASLR / CFG off in turn, and 32-bit SafeSEH
on and off. Every verdict matched the flags used, 64-bit SafeSEH is always
N/A, and a truncated `MZ` file and a bad PE signature are rejected cleanly
with exit code 2. (On the test machine MinGW could not be installed — the
package lists would not load — so the PE test files were built with a small
Python generator that writes minimal valid PE headers with chosen
`DllCharacteristics` flags; the MinGW commands above produce equivalent
real-world test files.)

## Defensive lesson: why RELRO plus bind-now matters

RELRO marks the Global Offset Table (GOT) read-only **after** the dynamic
linker has filled it in — so an attacker who gets a write primitive can no
longer overwrite a GOT entry and redirect a library call to their own code.

But RELRO alone is only half the job. Without bind-now, function addresses
are resolved **lazily**: the GOT stays writable until the first call to each
function, and the linker only marks it read-only afterwards. During that
window, a GOT-overwrite attack still works.

Bind-now (`-z now`) forces the linker to resolve every symbol **at load
time**, so the GOT can be made read-only immediately. That is the difference
between **partial RELRO** (segment present, lazy binding — the window stays
open) and **full RELRO** (segment + bind-now — the window is closed).

So when you ship a binary, always build with both flags together:

```bash
-Wl,-z,relro,-z,now
```

## Lab-only note

CanaryCheck is a lab tool for your own binaries. Build and test only on
systems you own or have written permission to test, inside an isolated lab
environment. Never test systems belonging to others without explicit written
authorization.

## License

MIT — see [LICENSE](LICENSE).
