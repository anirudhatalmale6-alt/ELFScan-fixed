#!/usr/bin/env python3
"""How often does ELFScan flag an ordinary system binary, and with what?
A detector that fires on everything is not a detector.  tests/run.py holds
this under a ceiling; this script shows the detail behind that number."""
import subprocess, sys, os, glob, collections

SCAN = os.path.abspath(sys.argv[1])
ARGS = sys.argv[2:] if len(sys.argv) > 2 else []

bins = []
for d in ("/usr/bin", "/bin", "/usr/sbin", "/usr/lib/x86_64-linux-gnu"):
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

bins = bins[:600]

kinds = collections.Counter()
flagged = []
errors = 0
biggest = []

for p in bins:
    try:
        r = subprocess.run([SCAN] + ARGS + [p], capture_output=True,
                           timeout=60, text=True, errors="replace")
    except subprocess.TimeoutExpired:
        errors += 1
        print("TIMEOUT", p)
        continue

    if r.returncode == 2:
        errors += 1
        continue

    hits = [l for l in r.stdout.splitlines() if l.startswith("[") and "SUMMARY" not in l]
    if hits:
        flagged.append(p)
        for l in hits:
            kinds[l.split("]")[0] + "]"] += 1
        for l in hits:
            if "len=" in l:
                try:
                    biggest.append((int(l.split("len=")[1].split()[0]), p))
                except ValueError:
                    pass

print("scanned      %d" % len(bins))
print("flagged      %d  (%.1f%%)" % (len(flagged), 100.0 * len(flagged) / max(1, len(bins))))
print("errors       %d" % errors)
for k, v in kinds.most_common():
    print("  %-18s %d" % (k, v))

biggest.sort(reverse=True)
print("\nlongest runs reported:")
for n, p in biggest[:8]:
    print("  %6d bytes  %s" % (n, p))
