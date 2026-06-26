#!/bin/bash

while true
do
    clear

    echo "==========================================="
    echo "        HOME SOC DASHBOARD"
    echo "==========================================="
    echo
    echo "1) System Inventory"
    echo "2) Network Scan"
    echo "3) Device Tracker"
    echo "4) Port Monitor"
    echo "5) Port Change Detector"
    echo "6) Log Analyzer"
    echo "7) File Integrity Monitor"
    echo "8) Exit"
    echo
    read -p "Select an option: " option

    case $option in
        1)
            ./scripts/inventory.sh
            ;;
        2)
            ./scripts/network_scan.sh
            ;;
        3)
            ./scripts/device_tracker.sh
            ;;
        4)
            ./scripts/port_monitor.sh
            ;;
        5)
            ./scripts/port_change_detector.sh
            ;;
        6)
            ./scripts/log_analyzer.sh
            ;;
        7)
            ./scripts/file_integrity_monitor.sh
            ;;
        8)
            echo "Goodbye!"
            exit
            ;;
        *)
            echo "Invalid option."
            ;;
    esac

    echo
    read -p "Press Enter to return to the menu..."
done
