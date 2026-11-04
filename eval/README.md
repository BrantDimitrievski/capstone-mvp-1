# eval test set

owasp benchmark has been on github for years, so an llm has probably seen it (and its answer key) in training.
a good score on it could just be memory. this folder is for testing secpipe on code the model hasn't seen.

two parts:

**1. our own samples** (`samples/`)
a small fake shop app we wrote ourselves, never published anywhere before this repo.
20 files, one per case: a vulnerable and a safe version for each cwe secpipe covers (22, 78, 89, 327, 328, 502, 798).
some of the safe ones are meant to look vulnerable (input overwritten before use, allowlist, prepared statement) to test false positives.
the answer key is `answers.csv`, kept outside `samples/` on purpose so the scanner never sees it.
no comments in the sample files either, so they don't give the answer away.

**2. real fix commits** (`fix-commits.csv`)
29 real security fixes from github in the cwes we cover. we scan the code right before the fix and check
if secpipe flags a file the fix changed. then we scan right after the fix to see if the finding goes away.
- 14 from [vul4j](https://github.com/tuhh-softsec/vul4j) (2013-2019, the model may have seen these)
- 15 from the [github advisory database](https://github.com/github/advisory-database) (sep 2025 - oct 2026, less likely to be in training)

comparing the old vs recent hit rate is one way to see if memory is helping.

**3. changed benchmark** (`mutate/`)
the two other ideas from the oct 21 meeting, done on owasp benchmark itself (the 5 categories secpipe covers, 1505 cases):
- mutate: same logic, different look. new class/package/variable/method names, no comments, class members shuffled.
  if secpipe only "remembers" benchmark files, its answers change here
- inject: take a safe sqli/cmdi/pathtraver case and add one line (`bar = param;`) right before the sink so user input reaches it.
  the file is now really vulnerable but the benchmark answer key still says safe, so memory would say safe
we don't reorder statements inside methods, too easy to change what the code does by accident.

## running it

needs jdk 21+, git, python 3. run from the repo root.

```bash
bash eval/run_samples.sh                       # our samples, ai off
AI=1 bash eval/run_samples.sh                  # same with ai on (set SECPIPE_LLM_KEY first)

bash eval/run_fix_commits.sh                   # all 29 fixes, ai off. slow, downloads each repo
ONLY=GHSA-89m4-43j5-vhhx bash eval/run_fix_commits.sh   # just one
AI=1 OUT=eval/out-ai bash eval/run_fix_commits.sh

BENCH=~/BenchmarkJava bash eval/mutate/run_mutations.sh       # benchmark original vs mutated vs injected, ~2 min
```

results go to `eval/out/` (ignored by git). each run prints a score table.

## files

- `answers.csv` - answer key for the samples
- `fix-commits.csv` - the fixes: repo, fix commit, cwe, and which files it changed
- `get_changed_files.py` - fills the changed_files column (already done, only rerun if you add rows)
- `run_samples.sh`, `run_fix_commits.sh` - run secpipe
- `score_samples.py`, `score_fix_commits.py`, `sarif_util.py` - scoring
- `mutate/Mutator.java` - makes the mutated / injected copies (uses javaparser from secpipe.jar, no extra deps)
- `mutate/run_mutations.sh`, `mutate/score_mutations.py` - run + compare

## notes

- a finding counts if it's in the right file with a matching cwe (close cwes count, e.g. 23 for 22)
- some fixes changed several files, a hit on any of them counts
- vul4j's one crypto case (esapi) is labeled cwe-310 there, we treat it as 327
