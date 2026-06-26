#!/bin/bash

echo "========================================"
echo "      HOME SOC - PORT MONITOR"
echo "========================================"

mkdir -p reports

ss -tuln > reports/open_ports.txt

echo
echo "Open ports saved to:"
echo "reports/open_ports.txt"

echo
echo "Current Listening Ports:"
echo "--------------------------------"

ss -tuln
