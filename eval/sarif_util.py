# small helpers shared by the two scorers

import json
import re

# tools label the same weakness at different levels, so accept close relatives
SAME_AS = {
    "22": {"22", "23", "36", "73"},
    "78": {"78", "77", "88"},
    "89": {"89", "564", "943"},
    "327": {"327", "326", "310", "757", "780"},
    "328": {"328", "916", "759", "760", "327"},
    "502": {"502"},
    "798": {"798", "321", "259"},
}

CWE_RE = re.compile(r"cwe[-_/ ]?0*(\d+)", re.I)


def cwes_in(obj):
    return set(CWE_RE.findall(json.dumps(obj)))


def load_findings(sarif_path):
    """returns a list of (file path, set of cwe numbers) from a sarif report"""
    with open(sarif_path, encoding="utf-8-sig") as f:
        sarif = json.load(f)

    out = []
    for run in sarif.get("runs", []):
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        by_id = {r.get("id"): cwes_in(r) for r in rules}
        for res in run.get("results", []):
            cwes = cwes_in(res.get("properties", {}))
            cwes |= by_id.get(res.get("ruleId"), set())
            idx = res.get("ruleIndex")
            if idx is not None and idx < len(rules):
                cwes |= cwes_in(rules[idx])
            cwes |= cwes_in(res.get("ruleId", ""))
            for loc in res.get("locations", []):
                uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                out.append((uri.replace("\\", "/"), cwes))
    return out


def flagged(findings, path_suffix, cwe):
    """true if any finding sits in a file ending with path_suffix and has a matching cwe"""
    ok = SAME_AS.get(cwe, {cwe})
    for uri, cwes in findings:
        if uri.endswith(path_suffix) and cwes & ok:
            return True
    return False
