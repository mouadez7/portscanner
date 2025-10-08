#!/usr/bin/python3

import sys
import getopt
from scapy.all import *
from scapy.layers.l2 import ARP, Ether

targets = ""


def usage():
    print("Simple Network Scanner - Network Security Testing")
    print("Usage: sudo python3 Host_Discovery.py -t TARGETS")
    print()
    print("Target Formats :")
    print("  Single IP:       192.168.1.7")
    print("  Multiple IPs:    192.168.1.1,192.168.1.7")
    print("  IP Range:        192.168.1.1-192.168.1.7")
    print("  Subnet:          192.168.1.0/24")
    print()
    print("Examples:")
    print("  sudo python3 Host_Discovery.py -t 192.168.1.7")
    print("  sudo python3 Host_Discovery.py -t 192.168.1.1,192.168.1.7")
    print("  sudo python3 Host_Discovery.py -t 192.168.1.1-192.168.1.7")
    print("  sudo python3 Host_Discovery.py -t 192.168.1.0/24")
    print()
    print("Note: Requires root privileges and scapy library")
    sys.exit(0)


def parse_targets(targets_str):
    ip_list = []

    if ',' not in targets_str and '-' not in targets_str and '/' not in targets_str:
        ip_list.append(targets_str)
    elif ',' in targets_str:
        for ip in targets_str.split(','):
            ip_list.append(ip.strip())
    elif '-' in targets_str:
        start_ip, end_ip = targets_str.split('-')
        start_parts = start_ip.split('.')
        end_parts = end_ip.split('.')

        for last_octet in range(int(start_parts[3]), int(end_parts[3]) + 1):
            ip_list.append(f"{start_parts[0]}.{start_parts[1]}.{start_parts[2]}.{last_octet}")
    elif '/' in targets_str:
        network = targets_str.split('/')[0]
        cidr = int(targets_str.split('/')[1])

        if cidr == 24:
            base = '.'.join(network.split('.')[:3])
            for i in range(1, 255):
                ip_list.append(f"{base}.{i}")

    else:
        print("[-] Invalid target format")
        usage()

    return ip_list


def scan_ip(ip):
    try:
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request

        responses = srp(arp_request_broadcast, timeout=2, verbose=0)[0]

        if len(responses) > 0:
            return responses[0][1].hwsrc
        return None

    except:
        return None


def main():
    global targets

    if not len(sys.argv[1:]):
        usage()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:", ["help", "targets="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-t", "--targets"):
            targets = a
        else:
            print("flag provided but not defined: " + o)
            usage()

    if not targets:
        print("[-] Targets are required")
        usage()

    ip_list = parse_targets(targets)

    print("[*] Starting scan for " + str(len(ip_list)) + " hosts")
    print("=" * 50)

    live_hosts = []

    for ip in ip_list:
        mac = scan_ip(ip)
        if mac:
            print("[+] " + ip + " - MAC: " + mac)
            live_hosts.append(ip)

    print("=" * 50)
    print("[*] Scan completed.")


if __name__ == "__main__":
    main()