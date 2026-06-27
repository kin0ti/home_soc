#!/usr/bin/env python3
"""
Home SOC
Main application launcher.
"""

import argparse

from python.scanners.network import main as network_scan
from python.core.inventory import main as inventory
from python.reports.reports import main as reports


def main():
    parser = argparse.ArgumentParser(
        description="Home SOC"
    )

    parser.add_argument(
        "command",
        choices=[
            "scan",
            "inventory",
            "report",
        ],
        help="Command to run",
    )

    args = parser.parse_args()

    if args.command == "scan":
        network_scan()

    elif args.command == "inventory":
        inventory()

    elif args.command == "report":
        reports()


if __name__ == "__main__":
    main()
