#!/bin/bash
# "attacker": scans and crafts packets against the slots.
set -euxo pipefail
dnf -y install nmap nmap-ncat python3-scapy || dnf -y install nmap nmap-ncat python3-pip
python3 -c 'import scapy' 2>/dev/null || pip3 install scapy
touch /var/run/natterjack-e2e-ready
