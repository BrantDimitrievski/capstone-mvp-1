#!/usr/bin/env python3
# fills the changed_files column in fix-commits.csv
# grabs just the fix commit + its parent from github (no file contents), then diffs them
# usage: python3 eval/get_changed_files.py

import csv
import os
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "fix-commits.csv")


def git(args, cwd):
    return subprocess.run(["git"] + args, cwd=cwd, capture_output=True, text=True)


def changed_files(repo, commit):
    with tempfile.TemporaryDirectory() as tmp:
        git(["init", "-q"], tmp)
        git(["remote", "add", "origin", f"https://github.com/{repo}.git"], tmp)
        r = git(["fetch", "-q", "--depth", "2", "--filter=blob:none", "origin", commit], tmp)
        if r.returncode != 0:
            print(f"  fetch failed for {repo}: {r.stderr.strip()[:120]}")
            return None
        r = git(["diff", "--name-only", f"{commit}~1", commit], tmp)
        files = [f for f in r.stdout.split() if f.endswith(".java")]
        # tests don't count, we only care about the code that got fixed
        return [f for f in files if "/test/" not in f and "/tests/" not in f and not f.startswith("test")]


rows = list(csv.DictReader(open(CSV_PATH)))
for row in rows:
    if row["changed_files"]:
        continue
    print(row["id"], row["repo"])
    files = changed_files(row["repo"], row["fix_commit"])
    if files is not None:
        row["changed_files"] = ";".join(files)

with open(CSV_PATH, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

missing = [r["id"] for r in rows if not r["changed_files"]]
print("done.", len(rows) - len(missing), "filled,", len(missing), "missing:", missing)
