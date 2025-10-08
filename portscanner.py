#!/usr/bin/python3

import sys
import getopt
import time
from scapy.all import *
from scapy.layers.inet import IP, TCP

target_ip = ""
ports = ""
timeout = 2


def usage():
    print("Port Scanner using Scapy - Network Security Testing")
    print("Usage: sudo python3 portscanner.py -i IP -p <port range>")
    print()
    print("Required Arguments:")
    print("  -i, --ip          Target IP address")
    print("  -p, --ports       Ports to scan (ex: 22 or 80,443 or 1-100)")
    print()
    print("Examples:")
    print("  sudo python3 portscanner.py -i 192.168.1.7 -p 80,443,22")
    print("  sudo python3 portscanner.py -i 192.168.1.7 -p 1-100")
    print("  sudo python3 portscanner.py -i 192.168.1.7 -p 80")
    print()
    print("Note: Requires root privileges and scapy library")
    sys.exit(0)


def scan_port(ip, port):
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=False)

        if response is None:
            return "filtered"
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
                return "open"
            elif response[TCP].flags == 0x14:
                return "closed"
        return "filtered"
    except Exception:
        return "error"


def parse_ports(ports_str):
    ports_list = []

    if ',' in ports_str:
        for port in ports_str.split(','):
            ports_list.append(int(port))
    elif '-' in ports_str:
        start, end = ports_str.split('-')
        ports_list.extend(range(int(start), int(end) + 1))
    else:
        ports_list.append(int(ports_str))

    return ports_list


def main():
    global target_ip, ports, timeout

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:p:",
                                   ["help", "ip=", "ports="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-i", "--ip"):
            target_ip = a
        elif o in ("-p", "--ports"):
            ports = a
        else:
            print("flag provided but not defined: " + o)
            usage()

    if not target_ip:
        print("[-] Target IP is required")
        usage()

    scan_ports = []

    if ports:
        scan_ports = parse_ports(ports)
    else:
        print("[-] Please specify ports to scan ")
        usage()

    print("[*] Starting scan for " + target_ip)
    print("=" * 50)

    start_time = time.time()
    open_ports = []

    for port in scan_ports:
        result = scan_port(target_ip, port)

        if result == "open":
            print("[+] Port " + str(port) + "/tcp is OPEN")
            open_ports.append(port)
        elif result != "open" and len(scan_ports) <= 10 :
            print("[-] Port " + str(port) + "/tcp is " + result.upper())

    end_time = time.time()

    print("=" * 50)
    print("[*] Scan completed in " + str(round(end_time - start_time, 2)) + " seconds")


if __name__ == "__main__":
    main()
