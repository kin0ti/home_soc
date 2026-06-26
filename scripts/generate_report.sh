#!/bin/bash

mkdir -p reports

TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT="reports/security_report_$TIMESTAMP.txt"

echo "=========================================" > "$REPORT"
echo "        HOME SOC SECURITY REPORT" >> "$REPORT"
echo "=========================================" >> "$REPORT"
echo "Generated: $(date)" >> "$REPORT"
echo "" >> "$REPORT"

echo "========== SYSTEM INVENTORY ==========" >> "$REPORT"
./scripts/inventory.sh >> "$REPORT"
echo "" >> "$REPORT"

echo "========== OPEN PORTS ==========" >> "$REPORT"
ss -tuln >> "$REPORT"
echo "" >> "$REPORT"

echo "========== DISK USAGE ==========" >> "$REPORT"
df -h >> "$REPORT"
echo "" >> "$REPORT"

echo "========== MEMORY ==========" >> "$REPORT"
free -h >> "$REPORT"
echo "" >> "$REPORT"

echo "========== RECENT AUTHENTICATION EVENTS ==========" >> "$REPORT"

if [ -f /var/log/auth.log ]; then
    tail -n 20 /var/log/auth.log >> "$REPORT"
else
    echo "Authentication log not found." >> "$REPORT"
fi

echo "" >> "$REPORT"
echo "=========================================" >> "$REPORT"
echo "End of Report" >> "$REPORT"

echo ""
echo "✅ Security report generated successfully!"
echo "Location: $REPORT"
