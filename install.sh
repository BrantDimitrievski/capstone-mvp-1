#!/usr/bin/env sh
# Builds secpipe and links the launcher into ~/.local/bin (or $PREFIX/bin).
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"

if ! command -v java >/dev/null 2>&1 && [ -z "$JAVA_HOME" ]; then
  echo "error: Java 21+ is required to build secpipe. Install a JDK (e.g. https://adoptium.net) first." >&2
  exit 2
fi

echo "Building secpipe..."
(cd "$ROOT" && ./mvnw -q -B package -DskipTests)

mkdir -p "$PREFIX/bin"
ln -sf "$ROOT/bin/secpipe" "$PREFIX/bin/secpipe"
chmod +x "$ROOT/bin/secpipe"

echo "Installed: $PREFIX/bin/secpipe"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "note: add $PREFIX/bin to your PATH, e.g. export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac
echo "Try: secpipe doctor && secpipe scan $ROOT/samples/vulnerable-java-app"
