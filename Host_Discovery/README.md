# Host_Discovery.py

Simple Network Scanner / Host Discovery

Description
-----------
A small host discovery script that sends ARP requests to identify live hosts on the local network.

Usage
-----
Usage: sudo python3 Host_Discovery.py -i TARGETS

Target Formats:
  Single IP:       192.168.1.7
  Multiple IPs:    192.168.1.1,192.168.1.7
  IP Range:        192.168.1.1-192.168.1.7
  Subnet:          192.168.1.0/24

Options:
  -t, --threads    Number of threads (default: 50, max: 200)

Examples:
  sudo python3 Host_Discovery.py -i 192.168.1.7
  sudo python3 Host_Discovery.py -i 192.168.1.1,192.168.1.7 -t 100
  sudo python3 Host_Discovery.py -i 192.168.1.1-192.168.1.7
  sudo python3 Host_Discovery.py -i 192.168.1.0/24

Note: Requires root privileges and scapy library
