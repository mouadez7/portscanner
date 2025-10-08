# Host_Discovery.py

Simple Network Scanner / Host Discovery

Description
-----------
A small host discovery script that sends ARP requests to identify live hosts on the local network.

Usage
-----
Usage: sudo python3 Host_Discovery.py -t TARGETS

Target Formats :
  Single IP:       192.168.1.7
  Multiple IPs:    192.168.1.1,192.168.1.7
  IP Range:        192.168.1.1-192.168.1.7
  Subnet:          192.168.1.0/24

Examples:
  sudo python3 Host_Discovery.py -t 192.168.1.7
  sudo python3 Host_Discovery.py -t 192.168.1.1,192.168.1.7
  sudo python3 Host_Discovery.py -t 192.168.1.1-192.168.1.7
  sudo python3 Host_Discovery.py -t 192.168.1.0/24