#!/bin/bash

mkdir -p reports
mkdir -p baseline

BASELINE="baseline/file_hashes.txt"
CURRENT="reports/current_hashes.txt"

echo "========================================"
echo "      HOME SOC - FILE INTEGRITY MONITOR"
echo "========================================"
echo ""

FILES=(
    "/etc/passwd"
    "/etc/hosts"
    "/etc/group"
)

> "$CURRENT"

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        sha256sum "$file" >> "$CURRENT"
    fi
done

if [ ! -f "$BASELINE" ]; then
    cp "$CURRENT" "$BASELINE"
    echo "Baseline created."
    echo "Run the script again to detect changes."
    exit 0
fi

echo "Checking file integrity..."
echo ""

if diff "$BASELINE" "$CURRENT" > /dev/null; then
    echo "✅ No file changes detected."
else
    echo "⚠️ File changes detected!"
    diff "$BASELINE" "$CURRENT"
fi
