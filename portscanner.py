#!/usr/bin/python3

import sys
import getopt
import time
import concurrent.futures
from scapy.all import *
from scapy.layers.inet import IP, TCP

target_ip = ""
ports = ""
timeout = 2
threads = 20


def usage():
    print("Port Scanner using Scapy - Network Security Testing")
    print("Usage: sudo python3 portscanner.py -i IP -p <port range> [options]")
    print()
    print("Required Arguments:")
    print("  -i, --ip          Target IP address")
    print("  -p, --ports       Ports to scan (ex: 22 or 80,443 or 1-100)")
    print()
    print("Options:")
    print("  -t, --threads     Number of threads (default: 20, max: 100)")
    print()
    print("Examples:")
    print("  sudo python3 portscanner.py -i 192.168.1.7 -p 80,443,22")
    print("  sudo python3 portscanner.py -i 192.168.1.7 -p 1-100 -t 50")
    print("  sudo python3 portscanner.py -i 192.168.1.7 -p 80")
    print()
    print("Note: Requires root privileges and scapy library")
    sys.exit(0)


def scan_port(port_data):
    ip, port, timeout_val = port_data
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout_val, verbose=False)

        if response is None:
            return port, "filtered"
        elif response.haslayer(TCP):
            if response[TCP].flags == 0x12:
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
                return port, "open"
            elif response[TCP].flags == 0x14:
                return port, "closed"
        return port, "filtered"
    except Exception:
        return port, "error"


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
    global target_ip, ports, timeout, threads

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hi:p:t:",
                                   ["help", "ip=", "ports=", "threads="])
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
        elif o in ("-t", "--threads"):
            threads = int(a)
            if threads > 100:
                print("[!] Maximum threads for port scanning is 100")
                threads = 100
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

    port_data = [(target_ip, port, timeout) for port in scan_ports]

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(scan_port, port_data)

        for port, result in results:
            if result == "open":
                print("[+] Port " + str(port) + "/tcp is OPEN")
                open_ports.append(port)
            elif result != "open" and len(scan_ports) <= 10:
                print("[-] Port " + str(port) + "/tcp is " + result.upper())

    end_time = time.time()

    print("=" * 50)
    print("[*] Scan completed in " + str(round(end_time - start_time, 2)) + " seconds")


if __name__ == "__main__":
    main()
