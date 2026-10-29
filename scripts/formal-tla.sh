#!/usr/bin/env bash
# Model-check every TLA+ spec under formal/tla with TLC (`make tla`).
#
#   formal/tla/<Spec>.cfg                 must hold (no violation)
#   formal/tla/violations/<Spec>[_x].cfg  must be violated: a known bug or
#                                         open question the model pins.
#                                         Passing means the code/model
#                                         changed; move the config.
#
# Needs Java 11+. tla2tools.jar is downloaded once into target/formal/
# (pinned version + SHA-256) unless TLA_TOOLS_JAR points at a copy.
set -euo pipefail

TLA_VERSION="v1.8.0"
TLA_SHA256="fc6878c603f0fdc18b9fe3e5bf51860cb90ab5b1154e3c371660c036d6bdd63e"
root="$(cd "$(dirname "$0")/.." && pwd)"
jar="${TLA_TOOLS_JAR:-$root/target/formal/tla2tools.jar}"

if [ ! -f "$jar" ]; then
    mkdir -p "$(dirname "$jar")"
    curl -fsSL -o "$jar.tmp" \
        "https://github.com/tlaplus/tlaplus/releases/download/$TLA_VERSION/tla2tools.jar"
    echo "$TLA_SHA256  $jar.tmp" | sha256sum -c - >/dev/null
    mv "$jar.tmp" "$jar"
fi

meta="$(mktemp -d)"
trap 'rm -rf "$meta"' EXIT
status=0

tlc() { # spec cfg
    java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -deadlock -workers auto \
        -metadir "$meta/$(basename "$2" .cfg)" -config "$2" "$1" 2>&1
}

cd "$root/formal/tla"
for cfg in *.cfg; do
    spec="${cfg%.cfg}.tla"
    if out="$(tlc "$spec" "$cfg")" && grep -q "No error has been found" <<<"$out"; then
        echo "ok        $cfg"
    else
        echo "FAIL      $cfg (expected to hold)"
        echo "$out" | grep -v -e '^Parsing file' -e '^Semantic processing' | tail -40
        status=1
    fi
done
for cfg in violations/*.cfg; do
    name="$(basename "$cfg" .cfg)"
    spec="${name%%_*}.tla"
    out="$(tlc "$spec" "$cfg" || true)"
    if grep -q "is violated" <<<"$out"; then
        echo "violated  $cfg (expected)"
    else
        echo "FAIL      $cfg (expected a violation)"
        echo "$out" | grep -v -e '^Parsing file' -e '^Semantic processing' | tail -40
        status=1
    fi
done
rm -f -- *_TTrace_*.tla *_TTrace_*.bin
exit "$status"
