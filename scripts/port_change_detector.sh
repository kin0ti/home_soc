#!/bin/bash

mkdir -p logs

CURRENT="logs/current_ports.txt"
PREVIOUS="logs/previous_ports.txt"

# Save previous scan
cp "$CURRENT" "$PREVIOUS" 2>/dev/null

# Capture current listening ports (sorted)
ss -tuln | sort > "$CURRENT"

echo "======================================="
echo " HOME SOC - PORT CHANGE DETECTOR"
echo "======================================="
echo

if [ -f "$PREVIOUS" ]; then
    echo "Comparing port scans..."
    echo

    if diff "$PREVIOUS" "$CURRENT" > /dev/null; then
        echo "✅ No port changes detected."
    else
        echo "⚠️ Port changes detected:"
        diff "$PREVIOUS" "$CURRENT"
    fi
else
    echo "First port scan completed."
fi
