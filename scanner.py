#!/usr/bin/env python3
# LAN Reconnaissance Tool - Module 1: ARP Discovery
import scapy.all as scapy
import argparse

def scan_network(ip_range):
    print(f"[*] Initializing Layer 2 ARP sweep for {ip_range}...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_frame / arp_request
    answered_list = scapy.srp(arp_packet, timeout=2, verbose=False)[0]
    
   
    active_devices = []
    for element in answered_list:
        device_info = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        active_devices.append(device_info)
        
    return active_devices

def display_results(devices):
    print("\nActive Devices Found:")
    print("-----------------------------------------")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="LAN Reconnaissance Tool")
    parser.add_argument("-t", "--target", dest="target", help="Target IP range (e.g., 192.168.1.1/24)", required=True)
    
    args = parser.parse_args()
    
    try:
        results = scan_network(args.target)
        display_results(results)
    except PermissionError:
        print("[!] Error: You need Administrator/Root privileges to craft raw packets.")
        print(f"[!] Try running: sudo python3 scanner.py -t {args.target}")