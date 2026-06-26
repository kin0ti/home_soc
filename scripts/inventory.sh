#!/bin/bash

echo "==================================="
echo "     HOME SOC - SYSTEM INVENTORY"
echo "==================================="

echo ""
echo "[Date]"
date

echo ""
echo "[Hostname]"
hostname

echo ""
echo "[Current User]"
whoami

echo ""
echo "[Operating System]"
grep PRETTY_NAME /etc/os-release

echo ""
echo "[Kernel Version]"
uname -r

echo ""
echo "[IP Address]"
hostname -I

echo ""
echo "[CPU]"
lscpu | grep "Model name"

echo ""
echo "[Memory]"
free -h

echo ""
echo "[Disk Usage]"
df -h

echo ""
echo "[Logged In Users]"
who

echo ""
echo "[Running Services]"
systemctl --type=service --state=running --no-pager
