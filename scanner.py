#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import socket
from threading import Thread
from mac_vendor_lookup import MacLookup, VendorNotFoundError

# Targeted ports for service enumeration
AUDIT_PORTS = [21, 22, 23, 80, 443, 8080, 8443]

def check_service(ip, port, found_ports):
    """Attempt TCP handshake to identify open services."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                found_ports.append(port)
    except:
        pass

def run_recon(target_range):
    print(f"[*] Starting discovery on: {target_range}")
    
    # Layer 2 Broadcast Discovery
    req = scapy.ARP(pdst=target_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    results_l2 = scapy.srp(broadcast/req, timeout=2, verbose=False)[0]
    
    mac_resolver = MacLookup()
    inventory = []

    for _, packet in results_l2:
        host_ip = packet.psrc
        host_mac = packet.hwsrc
        
        # OUI Resolution
        try:
            vendor = mac_resolver.lookup(host_mac)
        except (VendorNotFoundError, Exception):
            vendor = "Unknown/Randomized"
            
        # Multi-threaded Service Enumeration
        open_services = []
        scan_threads = []
        for port in AUDIT_PORTS:
            worker = Thread(target=check_service, args=(host_ip, port, open_services))
            scan_threads.append(worker)
            worker.start()
        
        for worker in scan_threads:
            worker.join()
            
        inventory.append({
            "ip": host_ip, 
            "mac": host_mac, 
            "vendor": vendor, 
            "services": open_services
        })
        
    return inventory

def format_output(host_list):
    print("\n" + "="*85)
    print(f"{'IP ADDRESS':<18} | {'MANUFACTURER':<25} | {'SERVICES'}")
    print("="*85)
    
    for host in host_list:
        svc_str = ", ".join(map(str, host['services'])) if host['services'] else "-"
        print(f"{host['ip']:<18} | {host['vendor']:<25} | {svc_str}")
    print("="*85 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Reconnaissance Utility")
    parser.add_argument("-t", "--target", help="Target CIDR (e.g. 192.168.1.0/24)", required=True)
    args = parser.parse_args()
    
    try:
        data = run_recon(args.target)
        format_output(data)
    except PermissionError:
        print("[!] Error: Root privileges required for raw packet injection.")
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")