#!/usr/bin/env python3
"""Malformed-ELF fuzzer.  A scanner is pointed at hostile files by
definition, so parsing one must never crash, hang or read out of bounds."""
import subprocess, sys, os, random, struct, tempfile

SCAN = os.path.abspath(sys.argv[1])
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
N = int(os.environ.get("FUZZ_N", 600))

BASE = sys.argv[3] if len(sys.argv) > 3 else "/bin/true"
base = open(BASE, "rb").read()

random.seed(SEED)

env = dict(os.environ)
env["ASAN_OPTIONS"] = "detect_leaks=1"
env["UBSAN_OPTIONS"] = "print_stacktrace=1"

# hand-built pathological headers
hand = []
hand.append(b"\x7fELF")
hand.append(b"\x7fELF" + b"\x00" * 12)
hand.append(b"\x7fELF\x02\x01" + b"\x00" * 100)
hand.append(b"\x7fELF\x01\x01" + b"\x00" * 100)
hand.append(b"\x7fELF\x03\x01" + b"\x00" * 100)   # bad class
hand.append(b"\x7fELF\x02\x02" + b"\x00" * 100)   # big endian
hand.append(b"\x00" * 4096)
hand.append(b"\x90" * 65536)
hand.append(b"\x7fELF\x02\x01" + b"\x90" * 65536)
hand.append(b"\xf3\xaa" * 5000)
hand.append(b"\xb0\x90" + b"\xf3\xaa" * 5000)
hand.append((b"\x66\x0f\x1f\x44\x00\x00") * 4000)

# ELF64 headers with extreme fields
for phoff, phnum, phentsize, shoff, shnum, shentsize in [
    (0xFFFFFFFFFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFF, 0xFFFF),
    (64, 0xFFFF, 56, 0, 0, 0),
    (64, 1, 0xFFFF, 0, 0, 0),
    (0, 0, 0, 64, 0xFFFF, 64),
    (0, 0, 0, 0xFFFFFFFF, 1, 64),
    (64, 0xFFFF, 0, 64, 0xFFFF, 0),
    (0xFFFFFFF0, 2, 56, 0xFFFFFFF0, 2, 64),
]:
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4] = 2
    eh[5] = 1
    struct.pack_into("<H", eh, 16, 2)        # e_type
    struct.pack_into("<H", eh, 18, 62)       # e_machine
    struct.pack_into("<Q", eh, 32, phoff)
    struct.pack_into("<Q", eh, 40, shoff)
    struct.pack_into("<H", eh, 54, phentsize)
    struct.pack_into("<H", eh, 56, phnum)
    struct.pack_into("<H", eh, 58, shentsize)
    struct.pack_into("<H", eh, 60, shnum)
    hand.append(bytes(eh))
    hand.append(bytes(eh) + b"\x90" * 4096)

# same for ELF32
for phoff, phnum, phentsize, shoff, shnum, shentsize in [
    (0xFFFFFFFF, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFF, 0xFFFF),
    (52, 0xFFFF, 32, 0, 0, 0),
    (0, 0, 0, 52, 0xFFFF, 40),
]:
    eh = bytearray(52)
    eh[0:4] = b"\x7fELF"
    eh[4] = 1
    eh[5] = 1
    struct.pack_into("<H", eh, 16, 2)
    struct.pack_into("<H", eh, 18, 3)
    struct.pack_into("<I", eh, 28, phoff)
    struct.pack_into("<I", eh, 32, shoff)
    struct.pack_into("<H", eh, 42, phentsize)
    struct.pack_into("<H", eh, 44, phnum)
    struct.pack_into("<H", eh, 46, shentsize)
    struct.pack_into("<H", eh, 48, shnum)
    hand.append(bytes(eh))
    hand.append(bytes(eh) + b"\x90" * 4096)

cases = list(hand)

# random mutations of a real binary, biased to the headers
for _ in range(N):
    b = bytearray(base)
    mode = random.randint(0, 3)
    if mode == 0:                                  # header bytes
        for _ in range(random.randint(1, 12)):
            i = random.randint(0, min(200, len(b) - 1))
            b[i] = random.randint(0, 255)
    elif mode == 1:                                # anywhere
        for _ in range(random.randint(1, 40)):
            i = random.randint(0, len(b) - 1)
            b[i] = random.randint(0, 255)
    elif mode == 2:                                # truncate
        b = b[:random.randint(1, len(b))]
    else:                                          # header + truncate
        for _ in range(random.randint(1, 8)):
            i = random.randint(0, min(200, len(b) - 1))
            b[i] = random.randint(0, 255)
        b = b[:random.randint(64, len(b))]
    cases.append(bytes(b))

bad = 0
seen = set()
for data in cases:
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(data)
        path = f.name
    for args in ([], ["-a"], ["-a", "-G", "-t", "1", "-s", "1"]):
        try:
            r = subprocess.run([SCAN] + args + [path], capture_output=True,
                               timeout=15, text=True, errors="replace", env=env)
            rc, err = r.returncode, r.stderr
        except subprocess.TimeoutExpired:
            rc, err = -99, "<<TIMEOUT>>"

        if rc < 0 or "Sanitizer" in err or "runtime error:" in err:
            bad += 1
            key = err.split("\n")[0][:140] or ("rc=%d" % rc)
            if key not in seen:
                seen.add(key)
                print("=" * 60)
                print("args=%s size=%d rc=%s" % (args, len(data), rc))
                print(err[:1800])
                open(os.path.join(os.path.dirname(SCAN),
                                  "crash-%d.bin" % len(seen)), "wb").write(data)
    os.unlink(path)

print("\n%d files x3 arg sets, %d runs crashed/hung/tripped a sanitizer"
      % (len(cases), bad))
