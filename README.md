# CodeAlpha Cybersecurity Internship - Task 1

## Project Title: Basic Network Sniffer

### Overview
This repository contains a functional network packet sniffer developed in Python using raw sockets (`AF_PACKET`) and binary structure unpacking (`struct` module). The tool captures live network traffic on Linux interfaces and decodes packet headers across multiple OSI model layers.

### Features
* **Raw Socket Interception:** Captures Ethernet frames directly from the network interface.
* **IPv4 Header Decoding:** Extracts version, header length, TTL, protocol type, and source/destination IP addresses.
* **Transport Layer Parsing:** Formats and decodes ICMP, TCP (including flags like SYN, ACK, FIN), and UDP traffic.
* **Payload Extraction:** Displays raw hex/text payload data for inspected packets.

---

### Requirements & Usage
* **OS:** Linux (Kali Linux / Ubuntu)
* **Python Version:** Python 3.x
* **Permissions:** Administrative (`sudo`) privileges required for raw socket access.

#### How to Run:
```bash
sudo python3 sniffer.py
