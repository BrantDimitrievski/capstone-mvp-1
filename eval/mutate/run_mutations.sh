#!/usr/bin/env bash
# makes mutated + injected copies of the owasp benchmark, scans them and the original, then compares
# usage: BENCH=~/BenchmarkJava bash eval/mutate/run_mutations.sh
#        AI=1 BENCH=... bash eval/mutate/run_mutations.sh   (ai on, needs SECPIPE_LLM_KEY or SECPIPE_LLM_URL)
set -euo pipefail

cd "$(dirname "$0")/../.."
BENCH="${BENCH:?set BENCH to your BenchmarkJava clone}"
OUT="${OUT:-eval/out}/mutations"
SEED="${SEED:-4907}"
JAR=target/secpipe.jar

[ -f "$JAR" ] || ./mvnw -q package -DskipTests

flags=(--no-tests --fail-on none -f sarif --category code)
[ "${AI:-0}" = "1" ] || flags+=(--no-ai)

mkdir -p "$OUT"
for mode in mutate inject; do
    rm -rf "$OUT/$mode"
    java -cp "$JAR" eval/mutate/Mutator.java "$BENCH" "$OUT/$mode" "$mode" "$SEED"
done

for target in orig mutate inject; do
    src="$OUT/$target"
    [ "$target" = "orig" ] && src="$BENCH"
    java ${JAVA_OPTS:--Xmx6g} -jar "$JAR" scan "$src" "${flags[@]}" -o "$OUT/scan-$target" > "$OUT/scan-$target.log" 2>&1 || true
done

python3 eval/mutate/score_mutations.py "$OUT/scan-orig/report.sarif" \
    "$OUT/mutate" "$OUT/scan-mutate/report.sarif" \
    "$OUT/inject" "$OUT/scan-inject/report.sarif" | tee "$OUT/score.txt"
