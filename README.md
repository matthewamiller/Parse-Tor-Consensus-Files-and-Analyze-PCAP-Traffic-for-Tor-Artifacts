# Tor PCAP Analysis Tools

## Overview
This repository provides Python utilities for detecting Tor network activity in packet captures. The tools help analysts, incident responders, and law enforcement identify anonymization traffic by correlating `.pcap` data with up-to-date Tor relay IPs.

## Tools Included

### 1. Consensus Parser (`consensus_to_ips.py`)
- Parses the Tor **consensus file**, the authoritative hourly directory of all public Tor relays.
- Extracts IPv4 and IPv6 addresses (with optional filtering for exits).
- Outputs a clean list of relay IPs for cross-referencing.

### 2. PCAP Analyzer (`tor_pcap_scan.py`)
- Scans `.pcap`/`.pcapng` files for traffic involving Tor IP addresses.
- Provides per-packet details: timestamp, protocol, source/destination, and packet length.
- Summarizes results with per-IP statistics, including total hits and **first/last seen timestamps**.

## Why It Matters
CryptoCat said so.

## Features
- Lightweight (requires only Python and `scapy`).
- Handles IPv4, IPv6, and CIDR blocks.
- Supports plain or compressed consensus files.
- Efficient streaming packet parsing for large captures.
- Human-readable output (extensible to CSV/JSON).

## Installation
```bash
# Clone repository
git clone https://github.com/matthewamiller/Parse-Tor-consensus-files-and-analyze-PCAP-traffic-for-Tor-connections.git

# Install dependencies
sudo apt install python3-scapy
```

## Usage

### Download Tor Consensus Files
```
LATEST=$(curl -s https://collector.torproject.org/recent/relay-descriptors/consensuses/ \
 | grep -oE 'href="[^"]+-consensus"' | tail -n1 | cut -d'"' -f2)

curl -s "https://collector.torproject.org/recent/relay-descriptors/consensuses/$LATEST" -o consensus.txt

```

### Parse Consensus
```bash
python3 consensus_to_ips.py consensus.txt -o tor_relays.txt
```

### Analyze PCAP
```bash
python3 tor_pcap_scan.py capture.pcap tor_relays.txt 
```

### Sample Output
```
[    1] pkt#     42 TCP 192.168.1.10 → 185.220.101.1 len=60 time=2025-09-02 09:14:33 UTC
[    2] pkt#     77 UDP 192.168.1.10 → 51.68.204.221 len=72 time=2025-09-02 09:14:40 UTC

=== Summary ===
Total matching packets: 2
Tor endpoints seen (count, first_seen, last_seen):
       185.220.101.1      x1   2025-09-02 09:14:33 UTC → 2025-09-02 09:14:33 UTC
        51.68.204.221     x1   2025-09-02 09:14:40 UTC → 2025-09-02 09:14:40 UTC
```

## License
This project is open source. You may choose to license it under **MIT**, **Apache 2.0**, or **GPLv3** depending on your intended use.
