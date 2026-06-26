#!/bin/bash

echo "=================================="
echo "HOME SOC - NETWORK SCANNER"
echo "=================================="

DATE=$(date +"%Y-%m-%d_%H-%M-%S")

NETWORK=$(ip route | awk '/kernel/ {print $1; exit}')

echo ""
echo "Scanning network: $NETWORK"

mkdir -p reports

nmap -sn $NETWORK > reports/network_scan_$DATE.txt

echo ""
echo "Scan complete."

echo "Results saved to: reports/network_scan_$DATE.txt"
