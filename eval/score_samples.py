#!/usr/bin/env python3
# scores a secpipe sarif report against our own sample files (answers.csv)
# usage: python3 eval/score_samples.py eval/out/samples/report.sarif

import csv
import os
import sys
from collections import defaultdict

from sarif_util import flagged, load_findings

HERE = os.path.dirname(os.path.abspath(__file__))

if len(sys.argv) < 2:
    sys.exit("usage: score_samples.py <report.sarif>")

findings = load_findings(sys.argv[1])
answers = list(csv.DictReader(open(os.path.join(HERE, "answers.csv"))))

per_cwe = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
lines = []
for a in answers:
    hit = flagged(findings, "/" + a["file"], a["cwe"])
    vuln = a["vulnerable"] == "true"
    if vuln and hit:
        result = "tp"
    elif vuln:
        result = "fn"
    elif hit:
        result = "fp"
    else:
        result = "tn"
    per_cwe[a["cwe"]][result] += 1
    lines.append((a["file"], a["cwe"], a["vulnerable"], result.upper(), a["why"]))

print(f"{'file':<24}{'cwe':<6}{'vuln':<7}{'result':<8}why")
for l in lines:
    print(f"{l[0]:<24}{l[1]:<6}{l[2]:<7}{l[3]:<8}{l[4]}")

total = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
print(f"\n{'cwe':<6}{'tp':>4}{'fn':>4}{'fp':>4}{'tn':>4}")
for cwe in sorted(per_cwe, key=int):
    c = per_cwe[cwe]
    print(f"{cwe:<6}{c['tp']:>4}{c['fn']:>4}{c['fp']:>4}{c['tn']:>4}")
    for k in total:
        total[k] += c[k]

tpr = total["tp"] / max(1, total["tp"] + total["fn"])
fpr = total["fp"] / max(1, total["fp"] + total["tn"])
print(f"\noverall: tpr {tpr:.0%}  fpr {fpr:.0%}  score {tpr - fpr:.0%}")
