#!/usr/bin/env python3

import scapy.all as scapy
import argparse
from mac_vendor_lookup import MacLookup, VendorNotFoundError

def scan_network(ip_range):
    print(f"[*] Initializing Layer 2 ARP sweep for {ip_range}...")
    
    # Create the ARP Request & Ethernet Broadcast Frame
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = broadcast_frame / arp_request
    
    # Send and receive packets
    answered_list = scapy.srp(arp_packet, timeout=2, verbose=False)[0]
    
    # Initialize the Vendor Lookup Database
    vendor_db = MacLookup()
    # Note: On very first run, it might need to download the database. 
    # If it fails, uncomment the next line once:
    # vendor_db.update_vendors()

    active_devices = []
    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        
        # --- MODULE 2: VENDOR IDENTIFICATION ---
        try:
            vendor = vendor_db.lookup(mac)
        except VendorNotFoundError:
            # Catch devices using Private/Randomized MAC addresses
            vendor = "Unknown (Randomized MAC)"
        except Exception:
            vendor = "Lookup Error"
            
        device_info = {"ip": ip, "mac": mac, "vendor": vendor}
        active_devices.append(device_info)
        
    return active_devices

def display_results(devices):
    print("\n[+] Network Scan Results:")
    print("-" * 80)
    # Professional formatting: left-aligned padding for clean columns
    print(f"{'IP Address':<18} | {'MAC Address':<20} | {'Manufacturer'}")
    print("-" * 80)
    
    for device in devices:
        print(f"{device['ip']:<18} | {device['mac']:<20} | {device['vendor']}")
    print("-" * 80)
    print(f"[*] Total devices found: {len(devices)}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LAN Reconnaissance Tool")
    parser.add_argument("-t", "--target", dest="target", help="Target IP range (e.g., 192.168.1.1/24)", required=True)
    args = parser.parse_args()
    
    try:
        results = scan_network(args.target)
        display_results(results)
    except PermissionError:
        print("[!] Error: Root/Sudo privileges required to craft raw packets.")
    except Exception as e:
        print(f"[!] An error occurred: {e}")