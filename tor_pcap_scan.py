#!/usr/bin/env python3
"""
tor_pcap_scan.py — find packets in a PCAP that touch known Tor IPs (or CIDR ranges),
and report per-IP first/last seen timestamps.

Requirements:
  pip install scapy

Usage:
  python tor_pcap_scan.py path/to/capture.pcap path/to/tor_ips.txt 
  # tor_ips.txt can contain lines like:
  # 51.68.204.221
  # 2a03:4000:6:43c::1
  # 185.220.101.0/24
"""

import argparse
import ipaddress
import datetime as dt
from scapy.all import PcapReader, IP, IPv6, TCP, UDP


def load_tor_indicators(path):
    ips = set()
    nets = []
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                if "/" in line:
                    nets.append(ipaddress.ip_network(line, strict=False))
                else:
                    ips.add(ipaddress.ip_address(line))  # autodetect v4/v6
            except ValueError:
                # ignore malformed lines
                pass
    return ips, nets


def ip_matches(addr_str, ips, nets):
    try:
        ip_obj = ipaddress.ip_address(addr_str)
    except ValueError:
        return False
    if ip_obj in ips:
        return True
    for net in nets:
        if ip_obj.version == net.version and ip_obj in net:
            return True
    return False


def proto_name(pkt):
    if TCP in pkt:
        return "TCP"
    if UDP in pkt:
        return "UDP"
    return pkt.lastlayer().name if pkt else "OTHER"


def fmt_utc(ts_float):
    # Scapy pkt.time is seconds since epoch (can be float); format as UTC
    return dt.datetime.utcfromtimestamp(float(ts_float)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + " UTC"


def main():
    parser = argparse.ArgumentParser(description="Scan PCAP for Tor IP matches (with per-IP first/last seen).")
    parser.add_argument("pcap", help="Path to .pcap/.pcapng")
    parser.add_argument("torlist", help="Path to Tor IP/CIDR list (one per line)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Show at most this many matching packet lines (default 50)")
    args = parser.parse_args()

    ips, nets = load_tor_indicators(args.torlist)
    if not ips and not nets:
        print("[!] No valid Tor indicators loaded.")
        return

    print(f"[+] Loaded {len(ips)} exact IPs and {len(nets)} networks from {args.torlist}")

    matches = 0
    shown = 0

    # Per-Tor-IP statistics:
    # ip_str -> {"count": int, "first": float_ts, "last": float_ts}
    tor_stats = {}

    try:
        with PcapReader(args.pcap) as pr:
            for i, pkt in enumerate(pr, start=1):
                # Extract L3 addresses
                src = dst = None
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif IPv6 in pkt:
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                else:
                    continue

                hit_src = ip_matches(src, ips, nets)
                hit_dst = ip_matches(dst, ips, nets)

                if not (hit_src or hit_dst):
                    continue

                matches += 1

                # Timestamp once per matching packet
                t = float(pkt.time)

                # Update per-IP first/last seen and counts for each Tor endpoint in this packet
                for addr, hit in ((src, hit_src), (dst, hit_dst)):
                    if not hit:
                        continue
                    entry = tor_stats.get(addr)
                    if entry is None:
                        tor_stats[addr] = {"count": 1, "first": t, "last": t}
                    else:
                        entry["count"] += 1
                        if t < entry["first"]:
                            entry["first"] = t
                        if t > entry["last"]:
                            entry["last"] = t

                # Print per-packet preview up to limit
                if shown < args.limit:
                    pn = proto_name(pkt)
                    length = len(pkt) if pkt else 0
                    direction = f"{src} → {dst}"
                    print(f"[{matches:>5}] pkt#{i:>7} {pn:<4} {direction} len={length} time={fmt_utc(t)}")
                    shown += 1

    except FileNotFoundError:
        print(f"[!] File not found: {args.pcap}")
        return
    except PermissionError:
        print(f"[!] Permission denied reading: {args.pcap}")
        return

    # Summary
    print("\n=== Summary ===")
    print(f"Total matching packets: {matches}")
    if tor_stats:
        print("Tor endpoints seen (count, first_seen, last_seen):")
        for ip_str, entry in sorted(tor_stats.items(),
                                    key=lambda kv: (-kv[1]['count'], kv[0])):
            print(f"  {ip_str:>40}  x{entry['count']:>6}  "
                  f"{fmt_utc(entry['first'])}  →  {fmt_utc(entry['last'])}")
    else:
        print("No Tor IPs found in this capture.")


if __name__ == "__main__":
    main()
