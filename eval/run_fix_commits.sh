#!/usr/bin/env bash
# for each real fix in fix-commits.csv:
#   1. grab the fix commit and the one before it
#   2. scan the code before the fix ("before") and after it ("after")
#   3. score: did secpipe flag the file the fix touched, and did it go away after
#
# usage: bash eval/run_fix_commits.sh                    (all, ai off)
#        ONLY=GHSA-89m4-43j5-vhhx bash eval/run_fix_commits.sh
#        AI=1 OUT=eval/out-ai bash eval/run_fix_commits.sh
# big repos (spring, jenkins, guava) take a while to download, so a full run is slow
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
OUT="${OUT:-eval/out}/fix-commits"
REPOS="${REPOS:-$HOME/.cache/secpipe-eval/repos}"
JAR="$ROOT/target/secpipe.jar"

[ -f "$JAR" ] || ./mvnw -q package -DskipTests
mkdir -p "$OUT" "$REPOS"

flags=(--no-tests --fail-on none -f sarif --category code)
[ "${AI:-0}" = "1" ] || flags+=(--no-ai)

tail -n +2 eval/fix-commits.csv | while IFS=, read -r id cve cwe repo commit source published files; do
    if [ -n "${ONLY:-}" ] && [ "$ONLY" != "$id" ]; then
        continue
    fi
    if [ -f "$OUT/$id/before/report.sarif" ]; then
        echo "$id: already done, skipping"
        continue
    fi

    echo "== $id ($repo, cwe-$cwe)"
    dir="$REPOS/${repo//\//_}"
    if [ ! -d "$dir/.git" ]; then
        git init -q "$dir"
        git -C "$dir" remote add origin "https://github.com/$repo.git"
    fi
    if ! git -C "$dir" fetch -q --depth 2 origin "$commit"; then
        echo "$id: couldn't fetch, skipping"
        continue
    fi

    for side in before after; do
        ref="$commit"
        [ "$side" = "before" ] && ref="$commit~1"
        git -C "$dir" checkout -q -f "$ref"
        mkdir -p "$OUT/$id/$side"
        # big repos (geotools, openam) run out of memory on the default heap
        java ${JAVA_OPTS:--Xmx6g} -jar "$JAR" scan "$dir" "${flags[@]}" -o "$OUT/$id/$side" > "$OUT/$id/$side/scan.log" 2>&1
        echo "  $side: done"
    done
done

python3 eval/score_fix_commits.py "$OUT" | tee "$OUT/score.txt"
