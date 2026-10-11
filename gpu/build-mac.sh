#!/bin/sh
# Builds the Metal vanity finder on macOS (needs Xcode Command Line Tools: xcode-select --install).
set -e
cd "$(dirname "$0")"
command -v swiftc >/dev/null || { echo "swiftc not found — run: xcode-select --install"; exit 1; }
command -v node >/dev/null || { echo "node not found — install Node.js 20+ (it verifies every match on the CPU)"; exit 1; }
[ -d ../node_modules ] || (cd .. && npm install)
swiftc -O gram-gpu.swift -o gram-gpu
echo "Built ./gpu/gram-gpu — running a 5s benchmark (includes the GPU self-test)..."
./gram-gpu --benchmark 5
