#!/usr/bin/env python3
# scores the fix commit runs made by run_fix_commits.sh
# "found" = secpipe flagged a file the real fix changed, with the right cwe, on the code before the fix
# "gone after fix" = that finding is no longer there on the fixed code
# usage: python3 eval/score_fix_commits.py [results dir, default eval/out/fix-commits]

import csv
import os
import sys

from sarif_util import flagged, load_findings

HERE = os.path.dirname(os.path.abspath(__file__))
results = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "out", "fix-commits")

rows = list(csv.DictReader(open(os.path.join(HERE, "fix-commits.csv"))))

print(f"{'id':<22}{'cwe':<6}{'source':<7}{'found':<7}{'gone after fix'}")
counts = {"vul4j": [0, 0], "ghsa": [0, 0]}  # [found, ran]
skipped = []
for r in rows:
    before = os.path.join(results, r["id"], "before", "report.sarif")
    after = os.path.join(results, r["id"], "after", "report.sarif")
    if not os.path.exists(before):
        skipped.append(r["id"])
        continue

    files = [f for f in r["changed_files"].split(";") if f]
    f_before = load_findings(before)
    found = any(flagged(f_before, f, r["cwe"]) for f in files)

    gone = "-"
    if found and os.path.exists(after):
        f_after = load_findings(after)
        gone = "yes" if not any(flagged(f_after, f, r["cwe"]) for f in files) else "no"

    counts[r["source"]][1] += 1
    if found:
        counts[r["source"]][0] += 1
    print(f"{r['id']:<22}{r['cwe']:<6}{r['source']:<7}{'yes' if found else 'no':<7}{gone}")

print()
for src, (found, ran) in counts.items():
    if ran:
        label = "old (vul4j, 2013-2019)" if src == "vul4j" else "recent (ghsa, 2025-2026)"
        print(f"{label}: found {found}/{ran} ({found / ran:.0%})")
if skipped:
    print("not run yet:", ", ".join(skipped))
