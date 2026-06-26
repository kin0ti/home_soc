#!/bin/bash

mkdir -p logs

SCAN_FILE="logs/current_devices.txt"
OLD_FILE="logs/previous_devices.txt"

cp "$SCAN_FILE" "$OLD_FILE" 2>/dev/null

nmap -sn 10.0.0.0/24 | grep "Nmap scan report for" | awk '{print $5}' > "$SCAN_FILE"



echo "================================="
echo " HOME SOC - DEVICE TRACKER "
echo "================================="
echo ""

if [ -f "$OLD_FILE" ]; then
    echo "Changes detected:"
    diff "$OLD_FILE" "$SCAN_FILE"
else
    echo "First scan completed."
fi
