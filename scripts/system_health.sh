#!/bin/bash

echo "==========================================="
echo "        HOME SOC - SYSTEM HEALTH"
echo "==========================================="
echo

echo "Hostname:"
hostname
echo

echo "Uptime:"
uptime -p
echo

echo "Load Average:"
uptime | awk -F'load average:' '{print $2}'
echo

echo "CPU Usage:"
top -bn1 | grep "%Cpu" | awk '{print "User: "$2"%  System: "$4"%  Idle: "$8"%"}'
echo

echo "Memory Usage:"
free -h
echo

echo "Disk Usage:"
df -h /
echo

echo "Top 5 Processes by CPU:"
ps -eo pid,comm,%cpu --sort=-%cpu | head -n 6
