#!/bin/bash
# "attacker": scans and crafts packets against the slots.
set -euxo pipefail
dnf -y install nmap nmap-ncat python3-scapy || dnf -y install nmap nmap-ncat python3-pip
if ! python3 -c 'import scapy' 2>/dev/null; then
	cat >/tmp/scapy-requirements.txt <<'REQ'
scapy==2.8.0 \
    --hash=sha256:abf855145ee829a42b2eb28983cd6a0a52b12a31d3f861cb7be36791195ed9aa \
    --hash=sha256:0eacd1f940d115611c1b8a4696f315b4b80caf2951e546893a3d0cd7f6bfd6fd
REQ
	pip3 install --require-hashes --no-deps -r /tmp/scapy-requirements.txt
fi
touch /var/run/natterjack-e2e-ready
