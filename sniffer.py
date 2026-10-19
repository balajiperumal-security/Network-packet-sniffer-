#!/usr/bin/env python3
"""Educational packet metadata viewer. Capture only on authorized networks."""
import argparse
from datetime import datetime
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS
except ImportError:
    raise SystemExit("Scapy missing. Run: python3 -m pip install -r requirements.txt")

def describe(p):
    src = dst = "-"
    proto = "OTHER"
    detail = ""
    if ARP in p:
        proto, src, dst = "ARP", p[ARP].psrc or "-", p[ARP].pdst or "-"
    elif IP in p:
        src, dst = p[IP].src, p[IP].dst
        if TCP in p:
            proto, detail = "TCP", f" ports={p[TCP].sport}->{p[TCP].dport}"
        elif UDP in p:
            proto, detail = "UDP", f" ports={p[UDP].sport}->{p[UDP].dport}"
        elif ICMP in p: proto = "ICMP"
    elif IPv6 in p:
        src, dst = p[IPv6].src, p[IPv6].dst
        if TCP in p:
            proto, detail = "TCPv6", f" ports={p[TCP].sport}->{p[TCP].dport}"
        elif UDP in p:
            proto, detail = "UDPv6", f" ports={p[UDP].sport}->{p[UDP].dport}"
        else: proto = "IPv6"
    if DNS in p: proto += "/DNS"
    print(f"[{datetime.now():%H:%M:%S}] {proto:<9} {src} -> {dst}{detail}")

def main():
    ap=argparse.ArgumentParser(description="Display packet metadata on an authorized network.")
    ap.add_argument("-i","--interface",help="network interface (optional)")
    ap.add_argument("-c","--count",type=int,default=30,help="packets to capture; 0 means continuous")
    a=ap.parse_args()
    if a.count < 0: ap.error("--count must be >= 0")
    print("CodeAlpha Task 1 — Network Sniffer")
    print("Metadata only. Use only with permission. Ctrl+C stops continuous capture.")
    try: sniff(iface=a.interface,prn=describe,count=a.count,store=False)
    except PermissionError: raise SystemExit("Permission denied; on Linux Mint try: sudo -E python3 sniffer.py")
    except OSError as e: raise SystemExit(f"Capture error: {e}. Check interface and permissions.")
if __name__=="__main__": main()
