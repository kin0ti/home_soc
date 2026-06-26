#!/bin/bash

echo "====================================="
echo " HOME SOC - NETWORK CHANGE DETECTOR "
echo "====================================="

LATEST=$(ls -t reports/network_scan_*.txt | head -1)
PREVIOUS=$(ls -t reports/network_scan_*.txt | head -2 | tail -1)

if [ -z "$PREVIOUS" ]; then
    echo "This is the first scan."
    echo "Run another network scan before comparing."
    exit 0
fi

echo ""
echo "Comparing:"
echo "$PREVIOUS"
echo "with"
echo "$LATEST"
echo ""

diff "$PREVIOUS" "$LATEST"
