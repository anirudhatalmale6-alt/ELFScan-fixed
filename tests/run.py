#!/usr/bin/env python3
"""
ELFScan test suite.

Three kinds of check, because they fail for different reasons:

  bytes   hand-built files scanned with -a, asserting the exact run length
          the matcher reports.  No compiler needed, and this is where an
          instruction-encoding mistake shows up.
  elf     real binaries built with gcc, asserting that a planted sled or
          generator is found and that a clean binary stays clean.
  budget  the false-positive rate over real system binaries, held under a
          ceiling so a new heuristic cannot quietly ruin the tool.

  ./run.py ../elfscan            run everything available
  ./run.py ../elfscan --verbose  show every check
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

SCAN = None
VERBOSE = False
passed = 0
failed = 0
skipped = 0
failures = []


def run_scan(path, args=()):
    r = subprocess.run([SCAN] + list(args) + [path], capture_output=True,
                       timeout=120, text=True, errors="replace")
    return r.stdout, r.stderr, r.returncode


def check(name, ok, detail=""):
    global passed, failed
    if ok:
        passed += 1
        if VERBOSE:
            print("pass  %s" % name)
    else:
        failed += 1
        failures.append((name, detail))
        print("FAIL  %s" % name)


def skip(name, why):
    global skipped
    skipped += 1
    print("skip  %s  (%s)" % (name, why))


# ---------------------------------------------------------------- bytes

NOP = {
    "nop":                b"\x90",
    "66 nop":             b"\x66\x90",
    "rex.w nop":          b"\x48\x90",
    "nopl (%rax)":        b"\x0f\x1f\x00",
    "nopl 0(%rax)":       b"\x0f\x1f\x40\x00",
    "nopl 0(%rax,%rax)":  b"\x0f\x1f\x44\x00\x00",
    "nopw 0(%rax,%rax)":  b"\x66\x0f\x1f\x44\x00\x00",
    "nopl 0(%rax) d32":   b"\x0f\x1f\x80\x00\x00\x00\x00",
    "nopl d32 sib":       b"\x0f\x1f\x84\x00\x00\x00\x00\x00",
    "nopw d32 sib":       b"\x66\x0f\x1f\x84\x00\x00\x00\x00\x00",
    "cs nopw 10-byte":    b"\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    "cs nopw 11-byte":    b"\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
    "cs nopw 12-byte":    b"\x66\x66\x66\x2e\x0f\x1f\x84\x00\x00\x00\x00\x00",
}

# things that must NOT be counted as NOPs
NOT_NOP = {
    "rex.b + 90 is xchg r8d,eax": b"\x41\x90",
    "0f 1f /1 is not the hint nop": b"\x0f\x1f\xc8",
    "0f 1e is endbr, not nop": b"\xf3\x0f\x1e\xfa",
    "plain 0f is nothing": b"\x0f\x0f\x0f\x0f",
    "ret is not a nop": b"\xc3",
}


def bytes_tests(tmp):
    for name, enc in NOP.items():
        reps = max(8, 400 // len(enc))
        blob = enc * reps
        want = len(blob)

        p = os.path.join(tmp, "nop.bin")
        with open(p, "wb") as f:
            f.write(b"\xc3" + blob + b"\xc3")

        out, _, _ = run_scan(p, ["-a", "-t", "16"])
        m = re.search(r"\[NOP_SLED\].*len=(\d+)", out)
        got = int(m.group(1)) if m else 0

        check("bytes: %s run of %d" % (name, want), got == want,
              "reported len=%d, wanted %d\n%s" % (got, want, out))

    for name, enc in NOT_NOP.items():
        blob = enc * 200
        p = os.path.join(tmp, "notnop.bin")
        with open(p, "wb") as f:
            f.write(blob)

        out, _, _ = run_scan(p, ["-a", "-t", "16"])
        check("bytes: %s" % name, "[NOP_SLED]" not in out,
              "unexpectedly reported a sled:\n" + out)

    # a slide run built from REX prefixes
    p = os.path.join(tmp, "slide.bin")
    with open(p, "wb") as f:
        f.write(b"\xc3" + b"\x41" * 300 + b"\xc3")

    out, _, _ = run_scan(p, ["-a", "-t", "100000"])
    m = re.search(r"\[SLIDE_RUN\].*len=(\d+).*dominant=0x41", out)
    check("bytes: 300-byte REX slide run", bool(m) and int(m.group(1)) == 300,
          out)

    # ...and it must be off when asked
    out, _, _ = run_scan(p, ["-a", "-t", "100000", "-s", "0"])
    check("bytes: -s 0 disables the slide detector", "[SLIDE_RUN]" not in out, out)

    # an all-0x90 run is a NOP sled, not a duplicate slide finding
    p = os.path.join(tmp, "nine.bin")
    with open(p, "wb") as f:
        f.write(b"\x90" * 300)

    out, _, _ = run_scan(p, ["-a"])
    check("bytes: a pure 0x90 run is not double-counted",
          out.count("[NOP_SLED]") == 1 and "[SLIDE_RUN]" not in out, out)

    # every rep stos form, in the order the assembler really emits
    for name, enc, want in [
        ("rep stosb", b"\xb0\x90" + b"\xf3\xaa", "rep stosb"),
        ("rep stosw", b"\x66\xb8\x90\x90" + b"\x66\xf3\xab", "rep stosw"),
        ("rep stosd", b"\xb8\x90\x90\x90\x90" + b"\xf3\xab", "rep stosd"),
        ("rep stosq", b"\x48\xc7\xc0\x90\x00\x00\x00" + b"\xf3\x48\xab", "rep stosq"),
    ]:
        p = os.path.join(tmp, "gen.bin")
        with open(p, "wb") as f:
            f.write(b"\xc3" * 8 + enc + b"\xc3" * 8)

        out, _, _ = run_scan(p, ["-a", "-t", "100000"])
        check("bytes: %s generator is found and named" % name,
              "[SLED_GEN]" in out and want in out, out)


# ------------------------------------------------------------------ elf

FIXTURES = {
    "clean": ("""
#include <stdio.h>
int main(void){ for(int i=0;i<3;i++) printf("%d\\n", i*i); return 0; }
""", []),

    "sled90": ("""
#include <stdio.h>
__attribute__((used,noinline)) static void s(void){
  __asm__ __volatile__(".rept 200\\n\\tnop\\n\\t.endr\\n\\tret\\n\\t"); }
int main(void){ printf("x\\n"); return 0; }
""", []),

    "sledcs": ("""
#include <stdio.h>
__attribute__((used,noinline)) static void s(void){
  __asm__ __volatile__(".rept 40\\n\\t"
    ".byte 0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00\\n\\t"
    ".endr\\n\\tret\\n\\t"); }
int main(void){ printf("x\\n"); return 0; }
""", []),

    "sledrex": ("""
#include <stdio.h>
__attribute__((used,noinline)) static void s(void){
  __asm__ __volatile__(".rept 300\\n\\t.byte 0x41\\n\\t.endr\\n\\tnop\\n\\tret\\n\\t"); }
int main(void){ printf("x\\n"); return 0; }
""", []),

    "genb": ("""
#include <stdlib.h>
int main(void){ char *b=malloc(4096);
  __asm__ __volatile__("mov $0x90,%%al\\n\\tmov %0,%%rdi\\n\\tmov $256,%%rcx\\n\\t"
    "rep stosb\\n\\t"::"r"(b):"al","rdi","rcx","memory");
  return b[0]==(char)0x90; }
""", []),

    "genw": ("""
#include <stdlib.h>
int main(void){ short *b=malloc(4096);
  __asm__ __volatile__("mov $0x9090,%%ax\\n\\tmov %0,%%rdi\\n\\tmov $128,%%rcx\\n\\t"
    "rep stosw\\n\\t"::"r"(b):"ax","rdi","rcx","memory");
  return b[0]==(short)0x9090; }
""", []),

    "execstack": ("""
#include <stdio.h>
int main(void){ printf("x\\n"); return 0; }
""", ["-z", "execstack"]),
}

EXPECT = {
    "clean":     ("none", None),
    "sled90":    ("[NOP_SLED]", 200),
    "sledcs":    ("[NOP_SLED]", 440),
    "sledrex":   ("[SLIDE_RUN]", 300),
    "genb":      ("[SLED_GEN]", None),
    "genw":      ("[SLED_GEN]", None),
    "execstack": ("[EXEC_STACK]", None),
}


def elf_tests(tmp):
    if not shutil.which("gcc"):
        skip("elf: all", "gcc not installed")
        return

    for name, (src, extra) in FIXTURES.items():
        c = os.path.join(tmp, name + ".c")
        b = os.path.join(tmp, name)

        with open(c, "w") as f:
            f.write(src)

        r = subprocess.run(["gcc", "-O0", "-o", b, c] + extra,
                           capture_output=True, text=True)
        if r.returncode != 0:
            skip("elf: %s" % name, "would not compile")
            continue

        out, _, rc = run_scan(b)
        want, wantlen = EXPECT[name]

        if want == "none":
            check("elf: %s is clean" % name,
                  rc == 0 and "findings=0" in out, out)
            continue

        ok = want in out
        if ok and wantlen is not None:
            m = re.search(re.escape(want) + r".*len=(\d+)", out)
            ok = bool(m) and int(m.group(1)) >= wantlen

        check("elf: %s reports %s" % (name, want), ok and rc == 1, out)


# --------------------------------------------------------------- budget

FP_CEILING = 0.05          # at most 5% of ordinary system binaries flagged


def budget_tests():
    import glob

    bins = []
    for d in ("/usr/bin", "/bin", "/usr/sbin"):
        for p in sorted(glob.glob(d + "/*")):
            if not os.path.isfile(p) or os.path.islink(p):
                continue
            try:
                with open(p, "rb") as f:
                    if f.read(4) != b"\x7fELF":
                        continue
            except OSError:
                continue
            bins.append(p)

    if len(bins) < 50:
        skip("budget: false-positive rate", "not enough system binaries here")
        return

    bins = bins[:400]
    flagged = 0

    for p in bins:
        try:
            out, _, rc = run_scan(p)
        except subprocess.TimeoutExpired:
            check("budget: %s does not hang" % p, False, "timed out")
            continue
        if rc == 1:
            flagged += 1

    rate = flagged / float(len(bins))
    check("budget: %d/%d system binaries flagged (%.1f%%, ceiling %.0f%%)"
          % (flagged, len(bins), rate * 100, FP_CEILING * 100),
          rate <= FP_CEILING,
          "the heuristics got noisier; check what changed before raising this")


def main():
    global SCAN, VERBOSE

    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    SCAN = os.path.abspath(sys.argv[1])
    VERBOSE = "--verbose" in sys.argv

    if not os.path.exists(SCAN):
        print("no such scanner: %s" % SCAN)
        return 2

    tmp = tempfile.mkdtemp(prefix="elfscan-test.")
    try:
        bytes_tests(tmp)
        elf_tests(tmp)
        budget_tests()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    for name, detail in failures:
        print("=" * 68)
        print(name)
        print(detail.strip()[:1500])

    print("\n%d passed, %d failed%s"
          % (passed, failed, (", %d skipped" % skipped) if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
