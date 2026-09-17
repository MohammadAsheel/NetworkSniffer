# CodeAlpha - Basic Network Sniffer & Protocol Analyzer

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Cyber Security](https://img.shields.io/badge/Domain-Cyber%20Security-red?style=for-the-badge)](https://en.wikipedia.org/wiki/Computer_security)
[![Task 1](https://img.shields.io/badge/Task-1%3A%20Basic%20Network%20Sniffer-green?style=for-the-badge)](https://www.codealpha.tech/)
[![CodeAlpha](https://img.shields.io/badge/Internship-CodeAlpha-orange?style=for-the-badge)](https://www.codealpha.tech/)

A modular, educational, and high-performance **Network Packet Sniffer & Protocol Analyzer** written in Python, developed for the **CodeAlpha Cyber Security Internship (Task 1)**.

The project demonstrates network packet capturing, layer-by-layer protocol dissection, real-time traffic statistics, and payload inspection using both **Scapy** and **Python Standard Library Raw Sockets (`struct.unpack`)**.

<p align="center">
  <img src="screenshots/TCP%20packet%20capture.png" alt="CodeAlpha Network Sniffer & Protocol Analyzer Preview" width="850"/>
</p>

---

## Table of Contents
1. [Overview & Objectives](#overview--objectives)
2. [Key Features](#key-features)
3. [Architecture & Protocol Dissection](#architecture--protocol-dissection)
4. [Installation & Setup](#installation--setup)
5. [Usage Guide](#usage-guide)
   - [Interactive Menu Mode](#1-interactive-menu-mode)
   - [Command-Line Options (CLI)](#2-command-line-options-cli)
   - [Raw Socket Engine (Pure Python)](#3-raw-socket-engine-pure-python)
6. [Sample Outputs & Analytics](#sample-outputs--analytics)
7. [Screenshots](#screenshots)
8. [Educational Deep Dive: How It Works](#educational-deep-dive-how-it-works)
9. [LinkedIn Video Demonstration Script](#linkedin-video-demonstration-script)
10. [Project Structure](#project-structure)
11. [Legal & Ethical Disclaimer](#legal--ethical-disclaimer)

---

## Overview & Objectives

As specified in the **CodeAlpha Cyber Security Internship Task 1**:
- **Capture network traffic packets** across active network interfaces.
- **Analyze captured packets** to understand their structure, headers, and payload contents.
- **Learn how data flows** across local networks and the Internet via fundamental protocols.
- **Use standard libraries** (`scapy` and `socket`) for packet capturing.
- **Display useful diagnostic information** including Source/Destination IP addresses, MAC addresses, transport protocols (TCP, UDP, ICMP), port services, TCP control flags, and formatted payload hex/ASCII dumps.

---

## Key Features

- 🚀 **Dual Sniffing Engines**:
  - **Scapy Engine**: Supports Berkeley Packet Filters (BPF), layer decoding, protocol heuristics, and native `.pcap` export for Wireshark.
  - **Raw Socket Engine**: Built with pure standard library (`socket` + `struct`), demonstrating low-level binary bit-shifting and header unpacking.
- 🔍 **Comprehensive Protocol Dissection**:
  - **Data Link (Layer 2)**: Ethernet II (Source/Destination MAC, EtherType), ARP (Request/Reply, Hardware/Protocol IP mapping).
  - **Network (Layer 3)**: IPv4 & IPv6 (Source/Destination IP, TTL, Protocol ID, Header Length, Packet ID).
  - **Transport (Layer 4)**: 
    - **TCP**: Source/Destination Ports, Sequence & Ack Numbers, Window Size, Control Flags (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
    - **UDP**: Datagram length, Source/Destination Ports.
    - **ICMP**: Type (Echo Request/Reply, Destination Unreachable), Code.
  - **Application (Layer 7)**: DNS queries and responses, plain HTTP methods (`GET`, `POST`, `HTTP/1.1`), and TLS handshake detection.
- 💻 **Wireshark-Style Hex & ASCII Payload Dump**:
  - Displays payload data side-by-side in 16-byte offset rows with hexadecimal values and printable ASCII text.
- 🎨 **Visual Terminal Interface (`rich`)**:
  - Color-coded protocol tags, formatted summary tables, adapter lists, and live statistics.
- 📊 **Real-time Session Analytics**:
  - Total packets, total traffic volume (KB/MB), capture duration, average throughput (packets/sec, KB/s).
  - Protocol distribution percentage table.
  - Top talkers (most active Source and Destination IP addresses).
- 💾 **PCAP Export**:
  - Save captured packets into industry-standard `.pcap` files ready for Wireshark inspection.

---

## Architecture & Protocol Dissection

```
                      +---------------------------------------+
                      |         Physical Network Card         |
                      +---------------------------------------+
                                          |
                        [Promiscuous / Capture Mode]
                                          |
               +--------------------------+--------------------------+
               |                                                     |
     [Scapy Engine Mode]                                  [Raw Socket Engine Mode]
     - BPF Filter Support                                 - Pure Python (socket + struct)
     - PCAP Export (wrpcap)                               - struct.unpack('!BBHHHBBH4s4s')
               |                                                     |
               +--------------------------+--------------------------+
                                          |
                                          v
                      [Packet Parser & Protocol Dissector]
       +-----------------------------------------------------------------------+
       |  Ethernet  |  MAC Addresses & EtherType                               |
       |  IPv4/IPv6 |  Source/Dest IPs, TTL, Protocol ID                       |
       |  TCP/UDP   |  Ports, Sequence/Ack, Flags (SYN/ACK/FIN), Service Name  |
       |  ICMP/ARP  |  Ping Request/Reply, ARP resolutions                     |
       |  Payload   |  Wireshark-style Hex + ASCII Dump Formatter              |
       +-----------------------------------------------------------------------+
                                          |
                                          v
                    [Rich Terminal UI, Analytics & CLI Menu]
                      All integrated in a single `sniffer.py`
```

---

## Installation & Setup

### 1. Prerequisites
- **Python**: Version 3.8 or higher.
- **Windows Users**: 
  - Ensure [Npcap](https://npcap.com/) is installed (installed by default if you have Wireshark installed).
  - Make sure to check the option *"Install Npcap in WinPcap API-compatible Mode"* during installation.
- **Administrative Privileges**:
  - Packet capturing requires elevated rights:
    - **Windows**: Run PowerShell or Command Prompt as **Administrator** (`Run as Administrator`).
    - **Linux/macOS**: Run with `sudo`.

### 2. Clone the Repository
```bash
git clone https://github.com/MohammadAsheel/CodeAlpha_Network_Sniffer.git
cd CodeAlpha_Network_Sniffer
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Interactive Menu Mode
The simplest way to run the sniffer is through the interactive CLI menu:
```bash
python sniffer.py
```
This presents a menu where you can choose preset filters, set packet limits, run simulations, or select output `.pcap` files:
```text
  1) Quick Start: Capture All Traffic (No filter)
  2) Web Traffic: HTTP / Web (Port 80, 8080)
  3) DNS Traffic: Queries & Responses (Port 53)
  4) TCP Traffic: Handshakes & Data (Filter: tcp)
  5) UDP Traffic: Datagrams & Streams (Filter: udp)
  6) ICMP Traffic: Ping Requests & Replies (Filter: icmp)
  7) Custom BPF Filter: Specify your own rule (e.g. host 192.168.1.1)
  8) Low-Level Raw Socket Engine (Pure Python Standard Library)
  9) List All Network Interfaces
  d) Multi-Protocol Demo Simulation (No Admin Required)
  p) Offline PCAP File Analysis (e.g. captures/demo.pcap)
  0) Exit
```

<p align="center">
  <img src="screenshots/Filter.png" alt="Interactive Menu & Protocol Filters" width="750"/>
</p>

### 2. Multi-Protocol Simulation (Demo Mode - No Admin Required)
If you want to immediately see the packet dissector, payload hex dump, and analytics without requiring Administrator privileges or live external traffic:
```bash
python sniffer.py --demo
```
This generates and parses synthetic packets across ARP, DNS, TCP 3-Way Handshake, HTTP GET/200 OK, ICMP Ping, and TLS Handshake.

### 3. Offline PCAP File Analysis
To dissect and inspect existing `.pcap` capture files offline:
```bash
python sniffer.py -r captures/demo.pcap
```

### 4. Command-Line Options (CLI)
You can directly pass command-line arguments:

```bash
# Run simulation demo
python sniffer.py --demo

# Dissect offline PCAP file
python sniffer.py -r captures/demo.pcap

# Capture 10 packets on default interface
python sniffer.py -c 10

# Capture 5 ICMP (Ping) packets
python sniffer.py -f "icmp" -c 5

# Capture DNS queries and responses
python sniffer.py -f "udp port 53" -c 15

# Capture web traffic and save to PCAP file
python sniffer.py -f "tcp port 80 or tcp port 8080" -o captures/web_traffic.pcap

# High-speed capture without printing payload hex dumps
python sniffer.py -c 100 --no-payload

# List all available network adapters with IP and MAC
python sniffer.py --list-interfaces
```

<p align="center">
  <img src="screenshots/Network%20interfaces.png" alt="Available Network Interfaces" width="750"/>
</p>

### 5. Raw Socket Engine (Pure Python)
To test low-level socket programming without Scapy:
```bash
python sniffer.py -m raw -c 10
```

---

## Sample Outputs & Analytics

### Live Packet Dissection & Hex Dump

<p align="center">
  <img src="screenshots/TCP%20packet%20capture.png" alt="TCP Packet Capture & TLS Inspection" width="750"/>
</p>

```text
Packet #1 [21:31:59.465] TCP   | Source IP Address: 192.168.31.37:51539 -> Destination IP Address: 172.217.118.4:443 (55 B) [HTTPS / TLS] Flags=[ACK] 
+─ Payload (1 bytes) ─────────────────────────────────────────────────────────+
| 0000   00                                                 .                 |
+─────────────────────────────────────────────────────────────────────────────+
Packet #2 [21:31:59.482] DNS   | Source IP Address: 192.168.31.232:5353 -> Destination IP Address: 224.0.0.251:5353 (103 B) DNS Query: _googlecast._tcp.local 
[+] Successfully saved 2 packets to: captures/capture.pcap
```

<p align="center">
  <img src="screenshots/UDP%20packet%20capture.png" alt="UDP Packet Capture & SSDP Payload" width="750"/>
</p>

### Session Analytics & Statistics

<p align="center">
  <img src="screenshots/Capture%20session%20analytics.png" alt="Capture Session Analytics" width="750"/>
</p>

```text
======================================================================
[*] CAPTURE SESSION ANALYTICS & SUMMARY
======================================================================
 Total Packets Captured:  2                           
 Total Traffic Volume:    0.15 KB (158 bytes)         
 Elapsed Time:            0.62 seconds                
 Average Throughput:      3.2 packets/sec | 0.25 KB/s 

Protocol Distribution:
+-----------------+--------------+--------------+
| Protocol        |      Packets |   Percentage |
+-----------------+--------------+--------------+
| TCP             |            1 |        50.0% |
| DNS             |            1 |        50.0% |
+-----------------+--------------+--------------+

Network Endpoints (Top IP Addresses & Packets):
+-------------------------+---------+------------------------------+---------+
| Top Source IP Addresses │ Packets │ Top Destination IP Addresses │ Packets |
+-------------------------+---------+------------------------------+---------+
| 192.168.31.37           │       1 │ 172.217.118.4                │       1 |
| 192.168.31.232          │       1 │ 224.0.0.251                  │       1 |
+-------------------------+---------+------------------------------+---------+
======================================================================
```

---

## Screenshots & Visual Showcase

The following high-resolution screenshots demonstrate the core functionalities and visual styling of the CodeAlpha Network Sniffer:

### 1. Interactive Menu & Protocol Filters
Guided terminal menu for selecting capture modes, BPF protocol filters, interface selection, simulation, and offline PCAP analysis.

<p align="center">
  <img src="screenshots/Filter.png" alt="Interactive Menu & Protocol Filters" width="800"/>
</p>

---

### 2. Available Network Interfaces Discovery
Automatic discovery and mapping of all network adapters (Wi-Fi, Ethernet, Loopback, Virtual adapters) with IPs and MACs.

<p align="center">
  <img src="screenshots/Network%20interfaces.png" alt="Available Network Interfaces" width="800"/>
</p>

---

### 3. Live TCP Packet Dissection & TLS Inspection
Dissecting TCP 3-way handshakes, control flags (`SYN`, `ACK`, `PSH`), sequence numbers, HTTPS/TLS identification, and hex/ASCII dumps.

<p align="center">
  <img src="screenshots/TCP%20packet%20capture.png" alt="TCP Packet Capture & TLS Inspection" width="800"/>
</p>

---

### 4. Live UDP & DNS Query Capture
Real-time capture of UDP datagrams, SSDP multicasts, and DNS queries with dual-column payload decoding.

<p align="center">
  <img src="screenshots/UDP%20packet%20capture.png" alt="UDP Datagrams and DNS Queries" width="800"/>
</p>

---

### 5. Capture Session Analytics & Traffic Summary
Post-capture analytical dashboard computing traffic volume, duration, packets/sec throughput, protocol distribution, and Top Talker endpoints.

<p align="center">
  <img src="screenshots/Capture%20session%20analytics.png" alt="Capture Session Analytics Summary" width="800"/>
</p>

---

## Educational Deep Dive: How It Works

### 1. How Packet Capture Works
Network cards typically ignore frames destined for other MAC addresses. When our sniffer runs in promiscuous mode (via Npcap on Windows or raw sockets), the network interface controller (NIC) passes all observed link-layer packets up to the operating system network stack, allowing Python to capture and dissect them.

### 2. IPv4 Header Structure
An IPv4 header is 20 to 60 bytes long:
- **Version & IHL (Byte 0)**: Indicates IPv4 and length of the header in 32-bit words (usually 5 = 20 bytes).
- **Total Length (Bytes 2-3)**: Entire packet size (header + data).
- **TTL (Time to Live, Byte 8)**: Decremented by each router hop to prevent infinite loops.
- **Protocol (Byte 9)**: `1` for ICMP, `6` for TCP, `17` for UDP.
- **Source & Destination IP (Bytes 12-19)**: 32-bit addresses converted via `socket.inet_ntoa()`.

### 3. TCP 3-Way Handshake & Flags
TCP establishes connections using flags:
1. `SYN` (Synchronize): Client initiates connection request.
2. `SYN-ACK` (Synchronize-Acknowledge): Server responds acknowledging sequence numbers.
3. `ACK` (Acknowledge): Client finalizes handshake; data exchange begins.
4. `FIN` / `RST`: Closes or resets the connection.

Our sniffer unpacks these flags dynamically to help security analysts identify scanning (e.g. `SYN` scans), active connections, and session terminations.

---

## LinkedIn Video Demonstration Script

As required by CodeAlpha instruction #4 (*"Post a video explanation of your project on LinkedIn with GitHub repo link"*), here is a ready-to-use **2-3 minute script** for your recording:

> **[Slide / Screen: Show VS Code / Terminal with CodeAlpha banner]**
>
> *"Hello everyone! I am thrilled to share my progress as a Cyber Security Intern at **@CodeAlpha**. Today, I am presenting my solution for **Task 1: Basic Network Sniffer & Protocol Analyzer**.*
>
> **[Demonstration Step 1: Launch interactive menu]**
>
> *"For this project, I built an advanced Python-based packet sniffer capable of capturing and dissecting live network traffic. I developed two independent capture engines:*
> 1. *A **Scapy Engine** supporting Berkeley Packet Filters and PCAP exports.*
> 2. *A **Pure Raw Socket Engine** using Python’s standard `socket` and `struct` libraries, unpacking binary headers byte-by-byte.*
>
> **[Demonstration Step 2: Run a live capture e.g. `python sniffer.py -c 10` or `python sniffer.py --demo`]**
>
> *"Here, you can see live network packets being captured in real-time. For every packet, our tool extracts:*
> - *Layer 2 MAC addresses and Layer 3 IPv4/IPv6 addresses.*
> - *Transport layer details, including TCP flags like SYN and ACK, sequence numbers, and UDP ports.*
> - *Application layer protocols such as DNS queries and HTTP requests.*
> - *And a Wireshark-style dual-column Hex and ASCII payload dump.*
>
> **[Demonstration Step 3: Show summary analytics]**
>
> *"Once capture completes, it automatically calculates session metrics: total bandwidth, throughput in packets per second, protocol distribution percentages, and the top talker IP endpoints. It also saves the traffic directly into a `.pcap` file for further deep-packet inspection in Wireshark!*
>
> **[Conclusion & Thank You]**
>
> *"This project gave me valuable hands-on experience with low-level network programming, the OSI model, and protocol security analysis. Thank you **@CodeAlpha** for this learning opportunity! The complete source code is linked below on GitHub. Thank you for watching!"*

---

## Project Structure

```
CodeAlpha_Network_Sniffer/
│
├── .gitignore              # Git ignore rules for Python caches, virtual environments, and PCAP logs
├── README.md               # Complete project documentation & presentation guide
├── requirements.txt        # Python dependencies (scapy, rich)
├── sniffer.py              # Complete unified network sniffer (Scapy + Raw Sockets + CLI + Analytics)
├── captures/               # Sample and saved .pcap captures
└── screenshots/            # Demonstration screenshots for documentation
```

---

## Running Verification & Demo

To run the packet dissection simulation verifying multi-protocol dissection (ARP, DNS, TCP Handshake, HTTP, ICMP, and TLS):
```bash
python sniffer.py --demo
```

To dissect and verify with an offline PCAP capture:
```bash
python sniffer.py -r captures/demo.pcap
```

---

## Legal & Ethical Disclaimer

> **⚠️ Warning**: This network packet sniffer is developed **strictly for educational, diagnostic, and authorized administrative purposes** as part of the CodeAlpha Cyber Security Internship. Unauthorized interception of network packets on networks where you do not have explicit permission is illegal and violates privacy laws. Always ensure you have authorization before capturing traffic on any network.
