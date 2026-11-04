#!/usr/bin/env python3
# compares secpipe on the original owasp benchmark vs the mutated / injected copies made by Mutator.java
# usage: python3 eval/mutate/score_mutations.py <original report.sarif> <out dir of mutate> <report.sarif of mutate> \
#                                               [<out dir of inject> <report.sarif of inject>]
#
# mutate: same cases, same answers, new look. if the score drops a lot, secpipe leans on how the code looks
# inject: safe cases made vulnerable with one line. the original answer was "safe", so a tool that
#         remembers the benchmark would keep saying safe. we want these flagged

import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from sarif_util import flagged, load_findings  # noqa: E402

if len(sys.argv) not in (4, 6):
    sys.exit(__doc__ or "see usage at the top of the file")

orig = load_findings(sys.argv[1])


def score(rows, hit):
    per = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    for r in rows:
        vuln = r["vulnerable"] == "true"
        h = hit(r)
        key = ("tp" if h else "fn") if vuln else ("fp" if h else "tn")
        per[r["category"]][key] += 1
    return per


def rates(c):
    tpr = c["tp"] / max(1, c["tp"] + c["fn"])
    fpr = c["fp"] / max(1, c["fp"] + c["tn"])
    return tpr, fpr


def total(per):
    t = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for c in per.values():
        for k in t:
            t[k] += c[k]
    return t


# mutate
labels = list(csv.DictReader(open(os.path.join(sys.argv[2], "labels.csv"))))
mut = load_findings(sys.argv[3])
before = score(labels, lambda r: flagged(orig, "/" + r["original"] + ".java", r["cwe"]))
after = score(labels, lambda r: flagged(mut, "/" + r["file"], r["cwe"]))

same = sum(flagged(orig, "/" + r["original"] + ".java", r["cwe"]) == flagged(mut, "/" + r["file"], r["cwe"])
           for r in labels)

print("mutation (same logic, renamed + reshuffled)")
print(f"{'category':<12}{'cases':>6}   {'original tpr/fpr/score':<24}{'mutated tpr/fpr/score'}")
for cat in sorted(before):
    n = sum(before[cat].values())
    b, a = rates(before[cat]), rates(after[cat])
    print(f"{cat:<12}{n:>6}   {b[0]:>5.0%} {b[1]:>5.0%} {b[0] - b[1]:>6.0%}       "
          f"{a[0]:>5.0%} {a[1]:>5.0%} {a[0] - a[1]:>6.0%}")
b, a = rates(total(before)), rates(total(after))
print(f"{'all':<12}{len(labels):>6}   {b[0]:>5.0%} {b[1]:>5.0%} {b[0] - b[1]:>6.0%}       "
      f"{a[0]:>5.0%} {a[1]:>5.0%} {a[0] - a[1]:>6.0%}")
print(f"same verdict on {same}/{len(labels)} cases ({same / len(labels):.1%})")

# inject
if len(sys.argv) == 6:
    labels = list(csv.DictReader(open(os.path.join(sys.argv[4], "labels.csv"))))
    inj = load_findings(sys.argv[5])
    print("\ninjection (safe cases made vulnerable with one line)")
    print(f"{'category':<12}{'cases':>6}{'flagged before':>16}{'flagged after':>15}")
    tot = [0, 0, 0]
    by = defaultdict(lambda: [0, 0, 0])
    for r in labels:
        b = flagged(orig, "/" + r["original"] + ".java", r["cwe"])
        a = flagged(inj, "/" + r["file"], r["cwe"])
        for x in (by[r["category"]], tot):
            x[0] += 1
            x[1] += b
            x[2] += a
    for cat in sorted(by):
        n, b, a = by[cat]
        print(f"{cat:<12}{n:>6}{b / n:>16.0%}{a / n:>15.0%}")
    n, b, a = tot
    print(f"{'all':<12}{n:>6}{b / n:>16.0%}{a / n:>15.0%}")
