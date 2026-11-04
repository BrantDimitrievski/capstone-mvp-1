# benchmark mutation + injection, ai off (2026-11-04)

`BENCH=~/BenchmarkJava bash eval/mutate/run_mutations.sh`, seed 4907, owasp benchmark v1.2, secpipe main.
only the 5 categories secpipe has rules for (1505 of 2740 cases).

## mutation (same logic, renamed + reshuffled)

| category | cases | original tpr / fpr / score | mutated tpr / fpr / score |
|---|---|---|---|
| cmdi | 251 | 90 / 88 / 2 | 90 / 88 / 2 |
| crypto | 246 | 100 / 0 / 100 | 100 / 0 / 100 |
| hash | 236 | 69 / 0 / 69 | 69 / 0 / 69 |
| pathtraver | 268 | 53 / 42 / 11 | 53 / 42 / 11 |
| sqli | 504 | 100 / 100 / 0 | 100 / 100 / 0 |
| all | 1505 | 85 / 56 / 30 | 85 / 56 / 30 |

same verdict on 1505/1505 cases.

## injection (490 safe cases made vulnerable with one line)

| category | cases | flagged before | flagged after |
|---|---|---|---|
| cmdi | 124 | 88% | 88% |
| pathtraver | 135 | 42% | 46% |
| sqli | 231 | 100% | 100% |
| all | 490 | 81% | 82% |

## what it means

- with ai off secpipe doesn't depend on names or layout at all, it gives the exact same answers. so the ai-off
  benchmark score isn't memory. this is the baseline to compare against once we run with ai on
- injection barely moves because the rules already flag most of the "safe" cases. for sqli and cmdi they flag
  any query/exec with a non constant string and don't follow where the value came from (that's the high fpr)
- so the real weakness is false positives on sqli/cmdi, not memory. that's what the ai triage step needs to fix,
  and the ai-on run of this same script will show if it does it by reasoning or by remembering
- crypto and hash are strong because they're just "which algorithm string is used"
