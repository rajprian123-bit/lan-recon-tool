#!/usr/bin/env python3
import scapy.all as scapy
import argparse
import socket
import json
from datetime import datetime
from threading import Thread
from mac_vendor_lookup import MacLookup, VendorNotFoundError
import matplotlib.pyplot as plt
from collections import Counter


AUDIT_PORTS = [22, 80, 443, 445, 554, 8008, 8080, 8443, 9100, 32400]

def check_service(ip, port, found_ports):
    """TCP handshake for service identification."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                found_ports.append(port)
    except:
        pass

def run_recon(target_range):
    print(f"[*] Starting discovery on: {target_range}")
    
    
    req = scapy.ARP(pdst=target_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    results_l2 = scapy.srp(broadcast/req, timeout=2, verbose=False)[0]
    
    mac_resolver = MacLookup()
    inventory = []

    for _, packet in results_l2:
        host_ip = packet.psrc
        host_mac = packet.hwsrc
        
        try:
            vendor = mac_resolver.lookup(host_mac)
        except:
            vendor = "Unknown/Randomized"
            
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

def export_results(data, filename="scan_results.json"):
    """Saves scan data to a JSON file with a timestamp."""
    log_data = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_devices": len(data),
        "devices": data
    }
    with open(filename, "w") as f:
        json.dump(log_data, f, indent=4)
    print(f"[+] Results exported to {filename}")

def format_output(host_list):
    print("\n" + "="*85)
    print(f"{'IP ADDRESS':<18} | {'MANUFACTURER':<25} | {'SERVICES'}")
    print("="*85)
    for host in host_list:
        svc_str = ", ".join(map(str, host['services'])) if host['services'] else "-"
        print(f"{host['ip']:<18} | {host['vendor']:<25} | {svc_str}")
    print("="*85 + "\n")

def visualize_network(data):
    """Generates a professional bar chart of network vendor distribution."""
    print("[*] Generating device analytics chart...")
    
    vendors = [host['vendor'] for host in data]
    vendor_counts = Counter(vendors)
    
    names = list(vendor_counts.keys())
    counts = list(vendor_counts.values())

    plt.figure(figsize=(10, 6))
    bars = plt.bar(names, counts, color='#3498db', edgecolor='#2980b9')
    
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.05, yval, ha='center', va='bottom')

    plt.xlabel('Manufacturer (Vendor)', fontweight='bold')
    plt.ylabel('Number of Devices', fontweight='bold')
    plt.title('Local Network Composition by Vendor', fontsize=14, fontweight='bold')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.tight_layout()
    plt.savefig("network_stats.png")
    print("[+] Success! Analytics chart saved as: network_stats.png")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Professional Network Audit Tool")
    parser.add_argument("-t", "--target", help="Target CIDR", required=True)
    parser.add_argument("-o", "--output", help="Output JSON filename", default="scan_results.json")
    args = parser.parse_args()
    
    try:
        # Runs the scan
        data = run_recon(args.target)
        format_output(data)
        # Data Persistence
        export_results(data, args.output)
        # Data Visualization
        visualize_network(data)
        
    except PermissionError:
        print("[!] Error: Root privileges required. Please use sudo.")