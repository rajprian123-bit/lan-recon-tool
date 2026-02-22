# LAN Recon Tool 

A lightweight, Python-based network discovery and vulnerability auditing tool. 

## Overview
This tool performs Layer 2 (Data Link) network reconnaissance using the Address Resolution Protocol (ARP). It is designed to identify active devices on a local area network, resolve hardware MAC addresses to their respective vendors, and flag potential endpoint vulnerabilities.

## Features (In Development)
- [ ] **ARP Network Sweep:** Fast, multithreaded discovery of all active IPs in a given CIDR range.
- [ ] **MAC OUI Resolution:** Automatic identification of device manufacturers/vendors.
- [ ] **Targeted Port Analysis:** Automated auditing of high-risk ports (e.g., Port 22/SSH) on discovered devices.

## Tech Stack
* **Language:** Python 3.x
* **Core Library:** Scapy (for raw packet crafting and network manipulation)