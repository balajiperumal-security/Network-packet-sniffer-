# Task 1 — Basic Network Sniffer

Shows timestamps, protocols, source/destination addresses, and TCP/UDP ports. Supports IPv4, IPv6, ARP, ICMP, TCP, UDP, and DNS metadata. Does not save captures or display payload contents.

## Linux Mint
```bash
cd Task1_Network_Sniffer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
sudo -E .venv/bin/python sniffer.py --count 30
```
To choose an interface, run `ip link`, then use `--interface YOUR_INTERFACE` with the actual interface name. Capture only on a network you own or have permission to inspect.
