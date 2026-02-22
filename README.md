# LAN Recon Tool

A **Python-based tool** for network discovery and security auditing. It performs **Layer 2 reconnaissance** to map active devices on a local network and analyzes their hardware and services.

## Overview
This script uses the **Address Resolution Protocol (ARP)** to identify active hosts in a CIDR range. It maps MAC addresses to vendors, scans for common open services using **multithreading**, and generates data reports for security analysis.

## Features
* **Network Discovery:** Uses Scapy to perform ARP sweeps across a subnet.
* **Vendor Identification:** Resolves hardware manufacturers via MAC OUI lookups.
* **Service Auditing:** Scans for high-risk ports (SSH, HTTP, SMB, etc.) using Python threads for speed.
* **JSON Export:** Saves all scan metadata and timestamps to a structured JSON file.
* **Data Visualization:** Uses Matplotlib to generate a bar chart (**network_stats.png**) showing device distribution by manufacturer.

## How to Use

### 1. Install Dependencies
Run this command in your terminal to install the required Python libraries:
`pip install scapy matplotlib mac_vendor_lookup`

### 2. Run the Scanner
You must use **sudo** because the script needs root privileges to craft raw network packets. Use the **-t** flag to set your network range.

**Example Command:**
`sudo python3 scanner.py -t 192.168.1.0/24`

*Note: Replace 192.168.1.0/24 with your actual network range (e.g., 10.0.0.0/24).*

## Output
1. **Terminal Table:** Shows a live summary of IPs, Vendors, and Ports.
2. **JSON File:** `scan_results.json` is generated for data logging.
3. **Analytics Chart:** `network_stats.png` is saved to visualize your network hardware.