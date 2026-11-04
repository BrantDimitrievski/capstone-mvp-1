#!/usr/bin/env bash
# scans our own sample app and scores it against answers.csv
# usage: bash eval/run_samples.sh          (ai off)
#        AI=1 bash eval/run_samples.sh     (ai on, needs SECPIPE_LLM_KEY or SECPIPE_LLM_URL set)
set -euo pipefail

cd "$(dirname "$0")/.."
OUT="${OUT:-eval/out}"
JAR=target/secpipe.jar

[ -f "$JAR" ] || ./mvnw -q package -DskipTests

flags=(--no-tests --fail-on none -f sarif,html)
mode=noai
if [ "${AI:-0}" = "1" ]; then
    mode=ai
else
    flags+=(--no-ai)
fi

dest="$OUT/samples-$mode"
mkdir -p "$OUT"
java -jar "$JAR" scan eval/samples "${flags[@]}" -o "$dest" > "$dest.log" 2>&1 || true
python3 eval/score_samples.py "$dest/report.sarif" | tee "$dest-score.txt"
