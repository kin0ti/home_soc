#!/bin/bash

mkdir -p reports

REPORT="reports/log_analysis_$(date +%F_%H-%M-%S).txt"

echo "=====================================" | tee "$REPORT"
echo "     HOME SOC - LOG ANALYZER" | tee -a "$REPORT"
echo "=====================================" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

if [ -f /var/log/auth.log ]; then
    LOGFILE="/var/log/auth.log"
elif [ -f /var/log/secure ]; then
    LOGFILE="/var/log/secure"
else
    echo "Authentication log not found." | tee -a "$REPORT"
    exit 1
fi

echo "Using log file: $LOGFILE" | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo "Failed login attempts:" | tee -a "$REPORT"
grep "Failed password" "$LOGFILE" | wc -l | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo "Successful logins:" | tee -a "$REPORT"
grep "Accepted password" "$LOGFILE" | wc -l | tee -a "$REPORT"
echo "" | tee -a "$REPORT"

echo "Last 10 authentication events:" | tee -a "$REPORT"
tail -n 10 "$LOGFILE" | tee -a "$REPORT"

echo ""
echo "Report saved to $REPORT"
