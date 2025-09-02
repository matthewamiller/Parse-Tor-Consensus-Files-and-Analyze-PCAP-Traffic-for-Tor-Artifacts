#!/usr/bin/env python3
# minimal_consensus_to_ips.py — tiny parser for plain-text Tor consensus

import argparse, ipaddress, sys

def clean(a: str) -> str:
    a = a.strip()
    if a.startswith("["):  # [v6]:port or [v6]
        return a[1:a.index("]")] if "]" in a else a.strip("[]")
    if a.count(":") == 1 and all(ch.isdigit() or ch in ".:" for ch in a):  # v4:port
        return a.split(":", 1)[0]
    # try as-is; if v6:port without brackets, split once from right
    try: ipaddress.ip_address(a); return a
    except: 
        core = a.rsplit(":", 1)[0] if ":" in a else a
        try: ipaddress.ip_address(core); return core
        except: return a

def parse(consensus_path, exits_only=False):
    ips, v4, extras, exitf = set(), None, [], False
    def flush():
        nonlocal v4, extras, exitf
        if exits_only and not exitf: pass
        else:
            for a in ([v4] if v4 else []) + extras:
                try: ips.add(str(ipaddress.ip_address(clean(a))))
                except: pass
        v4, extras, exitf = None, [], False

    with open(consensus_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith("r "):
                flush()
                parts = line.split()
                v4 = parts[6] if len(parts) >= 9 else None
            elif line.startswith("a "):
                extras.append(line.split(None, 1)[1].strip())
            elif line.startswith("s "):
                exitf = " Exit" in line or line.endswith(" Exit\n") or line.split().__contains__("Exit")
        flush()
    return ips

def main():
    ap = argparse.ArgumentParser(description="Extract IPs from a plain-text Tor consensus.")
    ap.add_argument("consensus", help="Path to decompressed consensus (plain text)")
    ap.add_argument("-o", "--out", default="consensus_ips.txt", help="Output file")
    ap.add_argument("--exits-only", action="store_true", help="Keep only Exit relays")
    args = ap.parse_args()

    ips = parse(args.consensus, exits_only=args.exits_only)
    with open(args.out, "w", encoding="utf-8") as w:
        for ip in sorted(ips, key=lambda s: (0 if ":" not in s else 1, s)):
            w.write(ip + "\n")
    print(f"[+] Wrote {len(ips)} IPs → {args.out}")

if __name__ == "__main__":
    main()
