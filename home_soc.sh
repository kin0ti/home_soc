#!/bin/bash

while true
do
    clear

    # ==========================================
    # System Information
    # ==========================================
    HOST=$(hostname)
    USER_NAME=$(whoami)
    CURRENT_DATE=$(date)
    KERNEL=$(uname -r)
    UPTIME=$(uptime -p)

    echo "=================================================="
    echo "               HOME SOC DASHBOARD"
    echo "=================================================="
    echo " Host    : $HOST"
    echo " User    : $USER_NAME"
    echo " Date    : $CURRENT_DATE"
    echo " Kernel  : $KERNEL"
    echo " Uptime  : $UPTIME"
    echo "=================================================="
    echo
    echo "1)  System Inventory"
    echo "2)  Network Scan"
    echo "3)  Device Tracker"
    echo "4)  Port Monitor"
    echo "5)  Port Change Detector"
    echo "6)  Log Analyzer"
    echo "7)  File Integrity Monitor"
    echo "8)  Generate Security Report"
    echo "9)  System Health Monitor"
    echo "10) Exit"
    echo

    read -p "Select an option: " option

    case $option in

        1)
            clear
            ./scripts/inventory.sh
            ;;

        2)
            clear
            ./scripts/network_scan.sh
            ;;

        3)
            clear
            ./scripts/device_tracker.sh
            ;;

        4)
            clear
            ./scripts/port_monitor.sh
            ;;

        5)
            clear
            ./scripts/port_change_detector.sh
            ;;

        6)
            clear
            ./scripts/log_analyzer.sh
            ;;

        7)
            clear
            ./scripts/file_integrity_monitor.sh
            ;;

        8)
            clear
            ./scripts/generate_report.sh
            ;;

        9)
            clear
            ./scripts/system_health.sh
            ;;

        10)
            echo
            echo "Thank you for using Home SOC!"
            exit 0
            ;;

        *)
            echo
            echo "Invalid option. Please select a number between 1 and 10."
            ;;
    esac

    echo
    read -p "Press Enter to return to the dashboard..."
done
