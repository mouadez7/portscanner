# portscanner.py

Simple TCP SYN Port Scanner using Scapy

Description
-----------
Lightweight TCP SYN port scanner that uses Scapy to send SYN packets and infer port state (open/closed/filtered).

Usage
-----
Usage: sudo python3 portscanner.py -i IP -p <port range> [options]

Required Arguments:
  -i, --ip          Target IP address
  -p, --ports       Ports to scan (ex: 22 or 80,443 or 1-100)

Options:
  -t, --threads     Number of threads (default: 20, max: 100)

Examples:
  sudo python3 portscanner.py -i 192.168.1.7 -p 80,443,22
  sudo python3 portscanner.py -i 192.168.1.7 -p 1-100 -t 50
  sudo python3 portscanner.py -i 192.168.1.7 -p 80

Note: Requires root privileges and scapy library
