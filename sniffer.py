"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
File: sniffer.py
Description: Complete, unified Network Packet Sniffer & Protocol Analyzer.
             Features:
               - Dual capture engines: Scapy engine (BPF filters, PCAP export)
                 and Pure Python Raw Socket engine (socket + struct unpacking).
               - Deep protocol dissection: Ethernet II, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, TLS.
               - Wireshark-style dual-column Hex and ASCII payload dump.
               - Real-time session analytics: throughput, protocol distribution, top talkers.
               - Interactive terminal menu and comprehensive CLI argument flags.
"""

import sys
import os
import time
import socket
import struct
import platform
import ctypes
import argparse
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, IntPrompt, Confirm

from scapy.all import sniff, wrpcap, conf, get_if_list, IFACES
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.packet import Raw

console = Console()

# ==============================================================================
# Protocol Mappings and Constants
# ==============================================================================

IP_PROTOCOLS: Dict[int, str] = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
}

ICMP_TYPES: Dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request (Ping)",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

PORT_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    79: "Finger",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS / TLS",
    445: "SMB",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

PROTOCOL_COLORS: Dict[str, str] = {
    "TCP": "cyan",
    "UDP": "green",
    "ICMP": "yellow",
    "ARP": "magenta",
    "DNS": "blue",
    "HTTP": "bright_red",
    "IPv6": "bright_magenta",
}


# ==============================================================================
# Data Structures
# ==============================================================================

@dataclass
class ParsedPacket:
    """Structured representation of a dissected network packet."""
    timestamp: str
    length: int
    summary: str
    protocol: str = "Unknown"
    ether_src: Optional[str] = None
    ether_dst: Optional[str] = None
    ip_version: Optional[int] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ttl: Optional[int] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    service: Optional[str] = None
    tcp_flags: Optional[str] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    icmp_type: Optional[str] = None
    dns_query: Optional[str] = None
    http_info: Optional[str] = None
    payload_len: int = 0
    payload_raw: bytes = b""
    payload_hex_ascii: str = ""
    extra_details: Dict[str, Any] = field(default_factory=dict)


# ==============================================================================
# Helper Functions: Formatting, Resolution, and Inspection
# ==============================================================================

def is_admin() -> bool:
    """Check if the current process has administrative / root privileges."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def format_hex_ascii(data: bytes, max_bytes: int = 128) -> str:
    """
    Format raw bytes into a classic Wireshark/tcpdump style dual-column Hex + ASCII dump.
    Example:
    0000   45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 02   E..<.@.@........
    """
    if not data:
        return ""

    truncated = False
    display_data = data
    if len(data) > max_bytes:
        display_data = data[:max_bytes]
        truncated = True

    lines: List[str] = []
    for offset in range(0, len(display_data), 16):
        chunk = display_data[offset : offset + 16]
        hex_part1 = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_part2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_part = f"{hex_part1:<23}  {hex_part2:<23}".strip()
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{offset:04x}   {hex_part:<48}   {ascii_part}")

    if truncated:
        lines.append(f"... ({len(data) - max_bytes} more bytes truncated)")

    return "\n".join(lines)


def get_service_name(port1: Optional[int], port2: Optional[int]) -> Optional[str]:
    """Resolve service name based on standard port numbers."""
    if port1 in PORT_SERVICES:
        return PORT_SERVICES[port1]
    if port2 in PORT_SERVICES:
        return PORT_SERVICES[port2]
    return None


def parse_tcp_flags(flags_val: Any) -> str:
    """Dissect TCP flag bits into clear active flag names (e.g. 'SYN, ACK')."""
    if flags_val is None:
        return ""
    try:
        val = int(flags_val)
        flags_map = [
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ]
        active = [name for mask, name in flags_map if val & mask]
        if active:
            return ", ".join(active)
    except Exception:
        pass
    return str(flags_val)


def get_default_host_ip() -> str:
    """Retrieve the primary local IPv4 address connected to the default network."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def get_available_interfaces() -> List[Dict[str, Any]]:
    """Retrieve list of available network interfaces with names and IPs."""
    interfaces = []
    try:
        for iface_name, iface_data in IFACES.items():
            name = getattr(iface_data, "name", iface_name)
            ip = getattr(iface_data, "ip", "N/A")
            mac = getattr(iface_data, "mac", "N/A")
            description = getattr(iface_data, "description", "")
            interfaces.append({
                "id": iface_name,
                "name": name,
                "ip": ip if ip else "N/A",
                "mac": mac if mac else "N/A",
                "description": description
            })
    except Exception:
        for iface_name in get_if_list():
            interfaces.append({
                "id": iface_name,
                "name": str(iface_name),
                "ip": "N/A",
                "mac": "N/A",
                "description": ""
            })
    return interfaces


def display_banner():
    """Display the project banner and environment metadata."""
    admin_status = "[bold green]YES (Elevated)[/bold green]" if is_admin() else "[bold red]NO (Elevated privileges recommended)[/bold red]"
    banner_text = (
        "[bold cyan]========================================================================[/bold cyan]\n"
        "[bold yellow]   ____          _        _    _       _             [/bold yellow]\n"
        "[bold yellow]  / ___|___   __| | ___  / \\  | |_ __ | |__   __ _   [/bold yellow]\n"
        "[bold yellow] | |   / _ \\ / _` |/ _ \\/ _ \\ | | '_ \\| '_ \\ / _` |  [/bold yellow]\n"
        "[bold yellow] | |__| (_) | (_| |  __/ ___ \\| | |_) | | | | (_| |  [/bold yellow]\n"
        "[bold yellow]  \\____\\___/ \\__,_|\\___/_/   \\_\\_| .__/|_| |_|\\__,_|  [/bold yellow]\n"
        "[bold yellow]                                 |_|                 [/bold yellow]\n"
        "[bold white]       TASK 1: BASIC NETWORK SNIFFER & PROTOCOL ANALYZER                [/bold white]\n"
        "[bold cyan]========================================================================[/bold cyan]\n"
        f"[dim]OS: {platform.system()} {platform.release()} | Python: {platform.python_version()} | Admin/Root: [/dim]{admin_status}"
    )
    console.print(Panel(banner_text, border_style="cyan", padding=(0, 1)))

    if not is_admin() and platform.system() == "Windows":
        console.print(
            "[bold yellow][!] NOTICE:[/bold yellow] You are currently running without Administrator privileges.\n"
            "[yellow]    On Windows, capturing live network packets often requires Administrator rights.\n"
            "    If you encounter permission errors, restart PowerShell / Command Prompt with 'Run as Administrator'.[/yellow]\n"
        )


def show_interfaces_table():
    """Display a clean table of all detected network interfaces."""
    interfaces = get_available_interfaces()
    table = Table(title="Available Network Interfaces", header_style="bold magenta", border_style="dim")
    table.add_column("#", justify="center", width=4)
    table.add_column("Interface Name", style="cyan", width=30)
    table.add_column("IPv4 Address", style="green", width=18)
    table.add_column("MAC Address", style="yellow", width=20)
    table.add_column("Description", style="white")

    for idx, iface in enumerate(interfaces, start=1):
        table.add_row(
            str(idx),
            str(iface["name"]),
            str(iface["ip"]),
            str(iface["mac"]),
            str(iface["description"])
        )
    console.print(table)
    return interfaces


# ==============================================================================
# Scapy Packet Dissection
# ==============================================================================

def parse_scapy_packet(pkt: Any, max_payload_dump: int = 128) -> ParsedPacket:
    """
    Parse a Scapy packet object into a standardized ParsedPacket dataclass.
    Handles Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP, and TLS payloads.
    """
    timestamp = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S.%f")[:-3]
    length = len(pkt)
    summary = pkt.summary()

    parsed = ParsedPacket(
        timestamp=timestamp,
        length=length,
        summary=summary,
    )

    # Layer 2: Ethernet
    if pkt.haslayer(Ether):
        parsed.ether_src = pkt[Ether].src
        parsed.ether_dst = pkt[Ether].dst

    # Layer 2.5: ARP
    if pkt.haslayer(ARP):
        parsed.protocol = "ARP"
        arp = pkt[ARP]
        op_name = "Request" if arp.op == 1 else ("Reply" if arp.op == 2 else str(arp.op))
        parsed.summary = f"ARP {op_name}: {arp.psrc} -> {arp.pdst} ({arp.hwsrc})"
        parsed.src_ip = arp.psrc
        parsed.dst_ip = arp.pdst
        parsed.extra_details["arp_op"] = op_name
        parsed.extra_details["arp_hwsrc"] = arp.hwsrc
        parsed.extra_details["arp_hwdst"] = arp.hwdst
        return parsed

    # Layer 3: Network Layer (IPv4 / IPv6)
    if pkt.haslayer(IP):
        ip = pkt[IP]
        parsed.ip_version = 4
        parsed.src_ip = ip.src
        parsed.dst_ip = ip.dst
        parsed.ttl = ip.ttl
        proto_num = ip.proto
        parsed.protocol = IP_PROTOCOLS.get(proto_num, f"Proto-{proto_num}")
        parsed.extra_details["ip_id"] = ip.id
        parsed.extra_details["ip_len"] = ip.len
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        parsed.ip_version = 6
        parsed.src_ip = ip6.src
        parsed.dst_ip = ip6.dst
        parsed.ttl = ip6.hlim
        proto_num = ip6.nh
        parsed.protocol = IP_PROTOCOLS.get(proto_num, f"IPv6-NextHeader-{proto_num}")

    # Layer 4: Transport Layer (TCP / UDP / ICMP)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        parsed.protocol = "TCP"
        parsed.src_port = tcp.sport
        parsed.dst_port = tcp.dport
        parsed.service = get_service_name(tcp.sport, tcp.dport)
        parsed.tcp_flags = parse_tcp_flags(tcp.flags)
        parsed.tcp_seq = tcp.seq
        parsed.tcp_ack = tcp.ack
        parsed.extra_details["window"] = tcp.window

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        parsed.protocol = "UDP"
        parsed.src_port = udp.sport
        parsed.dst_port = udp.dport
        parsed.service = get_service_name(udp.sport, udp.dport)
        parsed.extra_details["udp_len"] = udp.len

    elif pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        parsed.protocol = "ICMP"
        parsed.icmp_type = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
        parsed.extra_details["icmp_code"] = icmp.code

    # Layer 7: Application Protocols / Heuristics
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        parsed.protocol = "DNS"
        if dns.haslayer(DNSQR):
            qd = dns.getlayer(DNSQR)
            if qd and hasattr(qd, "qname"):
                qname_val = qd.qname
                qname = qname_val.decode("utf-8", errors="ignore") if hasattr(qname_val, "decode") else str(qname_val)
                parsed.dns_query = qname.rstrip(".")
            qr_type = "Response" if dns.qr == 1 else "Query"
            parsed.extra_details["dns_type"] = qr_type

    # Extract Raw Payload
    if pkt.haslayer(Raw):
        raw_bytes = bytes(pkt[Raw].load)
        parsed.payload_raw = raw_bytes
        parsed.payload_len = len(raw_bytes)
        parsed.payload_hex_ascii = format_hex_ascii(raw_bytes, max_bytes=max_payload_dump)

        # Detect plain HTTP
        if parsed.src_port in (80, 8080) or parsed.dst_port in (80, 8080):
            try:
                first_line = raw_bytes.split(b"\r\n", 1)[0].decode("latin-1", errors="ignore")
                if any(first_line.startswith(verb) for verb in ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "HTTP/"]):
                    parsed.http_info = first_line
                    parsed.protocol = "HTTP"
            except Exception:
                pass

        # Detect TLS Handshake
        if (parsed.src_port == 443 or parsed.dst_port == 443) and len(raw_bytes) >= 5:
            if raw_bytes[0] == 0x16:
                parsed.extra_details["tls_record"] = "TLS Handshake"
            elif raw_bytes[0] == 0x17:
                parsed.extra_details["tls_record"] = "TLS Application Data"

    return parsed


def generate_demo_packets() -> List[Any]:
    """Generate diverse synthetic packets covering ARP, DNS, TCP Handshake, HTTP, ICMP, and TLS."""
    packets = [
        # 1. ARP Request
        Ether(dst="ff:ff:ff:ff:ff:ff", src="00:11:22:33:44:55") /
        ARP(op=1, hwsrc="00:11:22:33:44:55", psrc="192.168.1.105", pdst="192.168.1.1"),

        # 2. ARP Reply
        Ether(dst="00:11:22:33:44:55", src="00:aa:bb:cc:dd:ee") /
        ARP(op=2, hwsrc="00:aa:bb:cc:dd:ee", psrc="192.168.1.1", pdst="192.168.1.105"),

        # 3. DNS Query
        Ether() / IP(src="192.168.1.105", dst="8.8.8.8", ttl=64) /
        UDP(sport=53421, dport=53) /
        DNS(rd=1, qd=DNSQR(qname="www.codealpha.tech")),

        # 4. DNS Response
        Ether() / IP(src="8.8.8.8", dst="192.168.1.105", ttl=56) /
        UDP(sport=53, dport=53421) /
        DNS(qr=1, ancount=1, qd=DNSQR(qname="www.codealpha.tech"), an=DNSRR(rrname="www.codealpha.tech", rdata="185.199.108.153")),

        # 5. TCP 3-Way Handshake: SYN
        Ether() / IP(src="192.168.1.105", dst="185.199.108.153", ttl=64) /
        TCP(sport=49200, dport=80, flags="S", seq=100000),

        # 6. TCP 3-Way Handshake: SYN-ACK
        Ether() / IP(src="185.199.108.153", dst="192.168.1.105", ttl=55) /
        TCP(sport=80, dport=49200, flags="SA", seq=500000, ack=100001),

        # 7. TCP 3-Way Handshake: ACK
        Ether() / IP(src="192.168.1.105", dst="185.199.108.153", ttl=64) /
        TCP(sport=49200, dport=80, flags="A", seq=100001, ack=500001),

        # 8. HTTP GET Request with Payload
        Ether() / IP(src="192.168.1.105", dst="185.199.108.153", ttl=64) /
        TCP(sport=49200, dport=80, flags="PA", seq=100001, ack=500001) /
        Raw(b"GET /index.html HTTP/1.1\r\nHost: www.codealpha.tech\r\nUser-Agent: CodeAlphaSniffer/1.0\r\nAccept: */*\r\n\r\n"),

        # 9. HTTP 200 OK Response with Payload
        Ether() / IP(src="185.199.108.153", dst="192.168.1.105", ttl=55) /
        TCP(sport=80, dport=49200, flags="PA", seq=500001, ack=100125) /
        Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><h1>CodeAlpha Task 1</h1></body></html>"),

        # 10. ICMP Echo (Ping) Request
        Ether() / IP(src="192.168.1.105", dst="1.1.1.1", ttl=64) /
        ICMP(type=8, code=0) /
        Raw(b"abcdefghijklmnopqrstuvwabcdefghi"),

        # 11. ICMP Echo (Ping) Reply
        Ether() / IP(src="1.1.1.1", dst="192.168.1.105", ttl=58) /
        ICMP(type=0, code=0) /
        Raw(b"abcdefghijklmnopqrstuvwabcdefghi"),

        # 12. HTTPS / TLS Handshake (Client Hello)
        Ether() / IP(src="192.168.1.105", dst="142.250.190.46", ttl=64) /
        TCP(sport=51432, dport=443, flags="PA") /
        Raw(b"\x16\x03\x01\x00\x55\x01\x00\x00\x51\x03\x03" + b"\x00" * 32 + b"\x20" + b"\x12" * 32),
    ]
    return packets


# ==============================================================================
# Pure Python Raw Socket Sniffer Engine
# ==============================================================================

class RawSocketSniffer:
    """
    Low-level raw socket packet sniffer using Python standard library (socket + struct).
    Demonstrates binary bit-shifting and header unpacking without third-party drivers.
    """

    def __init__(self, host_ip: Optional[str] = None):
        self.host_ip = host_ip or get_default_host_ip()
        self.sock: Optional[socket.socket] = None
        self.is_running = False
        self.packet_count = 0

    def start_sniffing(
        self,
        count: int = 0,
        packet_callback: Optional[Callable[[dict], None]] = None,
        verbose: bool = True
    ):
        """
        Start capturing packets via raw socket.
        :param count: Max packets to capture (0 = infinite)
        :param packet_callback: Optional callback receiving parsed packet dict
        :param verbose: Print formatted output to console
        """
        is_windows = platform.system() == "Windows"

        try:
            if is_windows:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.host_ip, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        except PermissionError:
            print("\n[!] ERROR: Administrator / Root privileges required for raw socket capturing.")
            print("    Please re-run this script in an elevated terminal ('Run as Administrator').\n")
            return
        except socket.error as e:
            print(f"\n[!] Socket creation error: {e}")
            print("    Ensure you are running with administrator privileges on interface:", self.host_ip)
            return

        self.is_running = True
        self.packet_count = 0
        print(f"[*] Raw Socket Sniffer bound to {self.host_ip}")
        print("[*] Capturing packets... (Press Ctrl+C to stop)\n")

        try:
            while self.is_running:
                raw_data, addr = self.sock.recvfrom(65535)
                self.packet_count += 1

                parsed = self._parse_packet(raw_data)

                if packet_callback:
                    packet_callback(parsed)
                elif verbose:
                    self._display_packet(parsed)

                if count > 0 and self.packet_count >= count:
                    break

        except KeyboardInterrupt:
            print("\n[*] Capture interrupted by user.")
        finally:
            self.stop()

    def _parse_packet(self, raw_data: bytes) -> dict:
        """Unpack IPv4 header, transport layer header, and payload."""
        timestamp = time.strftime("%H:%M:%S")

        # 1. Unpack IPv4 Header (First 20 bytes minimum)
        ip_header = raw_data[:20]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        ttl = iph[5]
        protocol_num = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])

        protocol_name = IP_PROTOCOLS.get(protocol_num, f"Proto-{protocol_num}")

        packet_info = {
            "timestamp": timestamp,
            "raw_len": len(raw_data),
            "ip_version": version,
            "ihl": ihl,
            "ttl": ttl,
            "protocol": protocol_name,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "icmp_type": None,
            "payload": b"",
            "payload_len": 0,
        }

        # 2. Unpack Transport Layer
        transport_data = raw_data[ihl:]

        if protocol_num == 6 and len(transport_data) >= 20:
            tcph = struct.unpack("!HHLLBBHHH", transport_data[:20])
            src_port = tcph[0]
            dst_port = tcph[1]
            seq_num = tcph[2]
            ack_num = tcph[3]
            offset_reserved = tcph[4]
            tcp_offset = (offset_reserved >> 4) * 4
            flags = tcph[5]

            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            packet_info["tcp_seq"] = seq_num
            packet_info["tcp_ack"] = ack_num
            packet_info["tcp_flags"] = parse_tcp_flags(flags)
            payload = transport_data[tcp_offset:]
            packet_info["payload"] = payload
            packet_info["payload_len"] = len(payload)

        elif protocol_num == 17 and len(transport_data) >= 8:
            udph = struct.unpack("!HHHH", transport_data[:8])
            src_port = udph[0]
            dst_port = udph[1]

            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            payload = transport_data[8:]
            packet_info["payload"] = payload
            packet_info["payload_len"] = len(payload)

        elif protocol_num == 1 and len(transport_data) >= 4:
            icmph = struct.unpack("!BBH", transport_data[:4])
            icmp_type = icmph[0]
            packet_info["icmp_type"] = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
            payload = transport_data[4:]
            packet_info["payload"] = payload
            packet_info["payload_len"] = len(payload)
        else:
            packet_info["payload"] = transport_data
            packet_info["payload_len"] = len(transport_data)

        return packet_info

    def _display_packet(self, p: dict):
        """Format and print dissected packet details to terminal."""
        proto = p["protocol"]
        src = f"{p['src_ip']}:{p['src_port']}" if p["src_port"] else p["src_ip"]
        dst = f"{p['dst_ip']}:{p['dst_port']}" if p["dst_port"] else p["dst_ip"]

        extra = []
        if p["tcp_flags"]:
            extra.append(f"Flags=[{p['tcp_flags']}]")
        if p["icmp_type"]:
            extra.append(f"ICMP=[{p['icmp_type']}]")

        extra_str = " ".join(extra)
        print(f"Packet #{self.packet_count} | [{p['timestamp']}] {proto:<5} | Source IP Address: {src} -> Destination IP Address: {dst} | Length: {p['raw_len']} Bytes {extra_str}")

        if p["payload_len"] > 0:
            dump = format_hex_ascii(p["payload"], max_bytes=64)
            print("   --- Payload Preview ---")
            for line in dump.splitlines():
                print(f"   {line}")
        print("-" * 75)

    def stop(self):
        """Clean up and close raw socket (disabling promiscuous mode)."""
        self.is_running = False
        if self.sock:
            try:
                if platform.system() == "Windows":
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        print(f"[*] Raw Socket closed. Total packets captured: {self.packet_count}")


# ==============================================================================
# Scapy Network Sniffer Engine
# ==============================================================================

class NetworkSniffer:
    """
    Main Scapy Network Packet Sniffer with live statistics and export capabilities.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        output_pcap: Optional[str] = None,
        offline_pcap: Optional[str] = None,
        show_payload: bool = True,
        max_payload_dump: int = 64,
        verbose: bool = True,
        packet_callback: Optional[Callable[[ParsedPacket], None]] = None,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.output_pcap = output_pcap
        self.offline_pcap = offline_pcap
        self.show_payload = show_payload
        self.max_payload_dump = max_payload_dump
        self.verbose = verbose
        self.custom_callback = packet_callback

        self.captured_packets: List[Any] = []
        self.stats_protocols: Counter = Counter()
        self.stats_src_ips: Counter = Counter()
        self.stats_dst_ips: Counter = Counter()
        self.total_bytes: int = 0
        self.total_packets: int = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self._stop_requested = False

    def _process_packet(self, pkt: Any):
        """Callback invoked by Scapy for each captured packet."""
        self.total_packets += 1
        pkt_len = len(pkt)
        self.total_bytes += pkt_len
        self.captured_packets.append(pkt)

        # Parse packet using our modular parser
        parsed = parse_scapy_packet(pkt, max_payload_dump=self.max_payload_dump)

        # Update statistics
        proto_key = parsed.protocol
        if parsed.dns_query:
            proto_key = "DNS"
        elif parsed.http_info:
            proto_key = "HTTP"

        self.stats_protocols[proto_key] += 1
        if parsed.src_ip:
            self.stats_src_ips[parsed.src_ip] += 1
        if parsed.dst_ip:
            self.stats_dst_ips[parsed.dst_ip] += 1

        # Execute custom callback if provided
        if self.custom_callback:
            self.custom_callback(parsed)

        # Verbose terminal rendering
        if self.verbose:
            self._render_packet(parsed)

    def _render_packet(self, p: ParsedPacket):
        """Render a single captured packet with Rich formatting."""
        color = PROTOCOL_COLORS.get(p.protocol, "white")

        src_str = f"{p.src_ip}:{p.src_port}" if p.src_port else (p.src_ip or "N/A")
        dst_str = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else (p.dst_ip or "N/A")

        line = Text()
        line.append(f"Packet #{self.total_packets} ", style="bold yellow")
        line.append(f"[{p.timestamp}] ", style="dim")
        line.append(f"{p.protocol:<5} | ", style=f"bold {color}")
        line.append("Source IP Address: ", style="bold cyan")
        line.append(f"{src_str} ", style="cyan")
        line.append("-> ", style="bold white")
        line.append("Destination IP Address: ", style="bold magenta")
        line.append(f"{dst_str} ", style="magenta")
        line.append(f"({p.length} B) ", style="dim")

        if p.service:
            line.append(f"[{p.service}] ", style="bold green")

        if p.tcp_flags:
            line.append(f"Flags=[{p.tcp_flags}] ", style="yellow")

        if p.icmp_type:
            line.append(f"ICMP={p.icmp_type} ", style="bold yellow")

        if p.dns_query:
            qr = p.extra_details.get("dns_type", "Query")
            line.append(f"DNS {qr}: {p.dns_query} ", style="bold blue")

        if p.http_info:
            line.append(f"HTTP: {p.http_info} ", style="bold bright_red")

        console.print(line)

        # Display payload hex/ASCII dump if present
        if self.show_payload and p.payload_len > 0:
            payload_title = f"Payload ({p.payload_len} bytes)"
            if p.http_info:
                payload_title += " [HTTP]"
            elif "tls_record" in p.extra_details:
                payload_title += f" [{p.extra_details['tls_record']}]"

            panel = Panel(
                Text(p.payload_hex_ascii, style="green"),
                title=f"[dim]{payload_title}[/dim]",
                title_align="left",
                border_style="dim",
                padding=(0, 1),
            )
            console.print(panel)

    def start(self):
        """Start capturing packets on the configured interface or offline PCAP."""
        self.start_time = time.time()
        self.captured_packets = []
        self._stop_requested = False

        source_info = f"Offline PCAP ({self.offline_pcap})" if self.offline_pcap else f"Interface ({self.interface or 'Default / All'})"
        if self.verbose:
            console.print(Panel.fit(
                f"[bold green]Starting Network Sniffer Engine[/bold green]\n"
                f"[cyan]Source:[/cyan] {source_info}\n"
                f"[cyan]Filter:[/cyan] {self.bpf_filter or 'None (Capturing All Traffic)'}\n"
                f"[cyan]Packet Limit:[/cyan] {self.packet_count if self.packet_count > 0 else 'Unlimited (or until end of capture)'}\n"
                f"[cyan]PCAP Export:[/cyan] {self.output_pcap or 'None'}",
                title="[bold yellow]Sniffer Configuration[/bold yellow]",
                border_style="yellow"
            ))
            if self.offline_pcap:
                console.print(f"[dim]Reading and analyzing packets from {self.offline_pcap}...[/dim]\n")
            else:
                console.print("[dim]Listening for incoming and outgoing network packets...[/dim]\n")

        try:
            sniff_kwargs: Dict[str, Any] = {
                "prn": self._process_packet,
                "store": True,
            }
            if self.offline_pcap:
                sniff_kwargs["offline"] = self.offline_pcap
            elif self.interface:
                sniff_kwargs["iface"] = self.interface

            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter
            if self.packet_count > 0:
                sniff_kwargs["count"] = self.packet_count

            sniff(**sniff_kwargs)

        except KeyboardInterrupt:
            console.print("\n[bold yellow][!] Sniffing stopped by user (Ctrl+C).[/bold yellow]")
        except PermissionError:
            console.print("\n[bold red][!] Permission Denied: Packet sniffing requires Administrator / Root privileges![/bold red]")
            console.print("[yellow]Please run your terminal or IDE as Administrator.[/yellow]")
        except Exception as e:
            console.print(f"\n[bold red][!] Sniffer Exception: {e}[/bold red]")
        finally:
            self.end_time = time.time()
            self._save_pcap()
            if self.verbose:
                self.print_summary()

    def run_demo(self, delay: float = 0.15):
        """Run simulated demonstration with synthetic multi-protocol packets."""
        self.start_time = time.time()
        self.captured_packets = []
        self._stop_requested = False

        if self.verbose:
            console.print(Panel.fit(
                "[bold green]Starting Multi-Protocol Demo Simulation[/bold green]\n"
                "[dim]Simulating live traffic: ARP, DNS Queries/Answers, TCP 3-Way Handshake, HTTP GET & 200 OK, ICMP Ping, and TLS Handshake.[/dim]\n"
                "[cyan]Mode:[/cyan] User Space Simulation (No Administrator privileges required)",
                title="[bold yellow]CodeAlpha Network Sniffer - Demo Mode[/bold yellow]",
                border_style="yellow"
            ))
            console.print("[dim]Injecting simulated packets into dissection pipeline...[/dim]\n")

        packets = generate_demo_packets()
        try:
            for pkt in packets:
                if self._stop_requested:
                    break
                if delay > 0:
                    time.sleep(delay)
                self._process_packet(pkt)
                if self.packet_count > 0 and self.total_packets >= self.packet_count:
                    break
        except KeyboardInterrupt:
            if self.verbose:
                console.print("\n[bold yellow][!] Demo interrupted by user.[/bold yellow]")
        finally:
            self.end_time = time.time()
            self._save_pcap()
            if self.verbose:
                self.print_summary()

    def _save_pcap(self):
        """Write captured packets to a .pcap file if output path configured."""
        if not self.output_pcap or not self.captured_packets:
            return

        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.output_pcap)), exist_ok=True)
            wrpcap(self.output_pcap, self.captured_packets)
            console.print(f"[bold green][+] Successfully saved {len(self.captured_packets)} packets to: {self.output_pcap}[/bold green]")
        except Exception as e:
            console.print(f"[bold red][!] Failed to write PCAP file: {e}[/bold red]")

    def print_summary(self):
        """Display an analytical summary of the sniffing session."""
        duration = max(self.end_time - self.start_time, 0.001)
        pps = self.total_packets / duration
        kbps = (self.total_bytes / 1024) / duration

        console.print("\n" + "=" * 70)
        console.print("[bold yellow][*] CAPTURE SESSION ANALYTICS & SUMMARY[/bold yellow]")
        console.print("=" * 70)

        # Overview Table
        meta_table = Table(show_header=False, box=None)
        meta_table.add_row("[bold cyan]Total Packets Captured:[/bold cyan]", f"[bold white]{self.total_packets:,}[/bold white]")
        meta_table.add_row("[bold cyan]Total Traffic Volume:[/bold cyan]", f"[bold white]{self.total_bytes / 1024:.2f} KB ({self.total_bytes:,} bytes)[/bold white]")
        meta_table.add_row("[bold cyan]Elapsed Time:[/bold cyan]", f"{duration:.2f} seconds")
        meta_table.add_row("[bold cyan]Average Throughput:[/bold cyan]", f"{pps:.1f} packets/sec | {kbps:.2f} KB/s")
        console.print(meta_table)

        # Protocol Breakdown Table
        if self.stats_protocols:
            console.print("\n[bold]Protocol Distribution:[/bold]")
            proto_table = Table(show_header=True, header_style="bold magenta")
            proto_table.add_column("Protocol", style="cyan", width=15)
            proto_table.add_column("Packets", justify="right", width=12)
            proto_table.add_column("Percentage", justify="right", width=12)

            for proto, count in self.stats_protocols.most_common():
                pct = (count / self.total_packets) * 100 if self.total_packets > 0 else 0
                proto_table.add_row(proto, f"{count:,}", f"{pct:.1f}%")
            console.print(proto_table)

        # Top Talkers
        if self.stats_src_ips or self.stats_dst_ips:
            talker_table = Table(show_header=True, header_style="bold blue")
            talker_table.add_column("Top Source IP Addresses", style="cyan")
            talker_table.add_column("Packets", justify="right")
            talker_table.add_column("Top Destination IP Addresses", style="magenta")
            talker_table.add_column("Packets", justify="right")

            top_src = self.stats_src_ips.most_common(5)
            top_dst = self.stats_dst_ips.most_common(5)
            max_rows = max(len(top_src), len(top_dst))

            for i in range(max_rows):
                src_str = top_src[i][0] if i < len(top_src) else ""
                src_cnt = str(top_src[i][1]) if i < len(top_src) else ""
                dst_str = top_dst[i][0] if i < len(top_dst) else ""
                dst_cnt = str(top_dst[i][1]) if i < len(top_dst) else ""
                talker_table.add_row(src_str, src_cnt, dst_str, dst_cnt)

            console.print("\n[bold]Network Endpoints (Top IP Addresses & Packets):[/bold]")
            console.print(talker_table)

        console.print("=" * 70 + "\n")


# ==============================================================================
# Interactive Guided Menu
# ==============================================================================

def interactive_menu():
    """Interactive guided menu for interns to easily explore and capture network traffic."""
    while True:
        display_banner()
        console.print("[bold]Select a Sniffing Mode or Protocol Filter:[/bold]\n")
        console.print("  [bold cyan]1)[/bold cyan] Quick Start: Capture All Traffic (No filter)")
        console.print("  [bold cyan]2)[/bold cyan] Web Traffic: HTTP / Web (Port 80, 8080)")
        console.print("  [bold cyan]3)[/bold cyan] DNS Traffic: Queries & Responses (Port 53)")
        console.print("  [bold cyan]4)[/bold cyan] TCP Traffic: Handshakes & Data (Filter: tcp)")
        console.print("  [bold cyan]5)[/bold cyan] UDP Traffic: Datagrams & Streams (Filter: udp)")
        console.print("  [bold cyan]6)[/bold cyan] ICMP Traffic: Ping Requests & Replies (Filter: icmp)")
        console.print("  [bold cyan]7)[/bold cyan] Custom BPF Filter: Specify your own rule (e.g. host 192.168.1.1)")
        console.print("  [bold cyan]8)[/bold cyan] Low-Level Raw Socket Engine (Pure Python Standard Library)")
        console.print("  [bold cyan]9)[/bold cyan] List All Network Interfaces")
        console.print("  [bold green]d)[/bold green] Multi-Protocol Demo Simulation (No Admin Required)")
        console.print("  [bold magenta]p)[/bold magenta] Offline PCAP File Analysis (e.g. captures/demo.pcap)")
        console.print("  [bold cyan]0)[/bold cyan] Exit\n")

        choice = Prompt.ask(
            "[bold yellow]Enter your choice[/bold yellow]",
            choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "d", "D", "p", "P"],
            default="1"
        ).lower()

        if choice == "0":
            console.print("[bold green]Thank you for using CodeAlpha Network Sniffer. Goodbye![/bold green]")
            sys.exit(0)

        if choice == "d":
            console.print("\n[bold green]Launching Multi-Protocol Demo Simulation...[/bold green]")
            save_pcap = Confirm.ask("Do you want to save the demo packets to a .pcap file?", default=False)
            output_pcap = None
            if save_pcap:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_pcap = f"captures/demo_capture_{timestamp}.pcap"
            show_payload = Confirm.ask("Display payload Hex/ASCII dump?", default=True)
            sniffer = NetworkSniffer(output_pcap=output_pcap, show_payload=show_payload)
            sniffer.run_demo()
            Prompt.ask("\nPress [bold yellow]Enter[/bold yellow] to return to the main menu")
            console.clear()
            continue

        if choice == "p":
            pcap_path = Prompt.ask("Enter path to .pcap file", default="captures/demo.pcap")
            if not os.path.exists(pcap_path):
                console.print(f"[bold red]File not found: {pcap_path}[/bold red]")
            else:
                show_payload = Confirm.ask("Display payload Hex/ASCII dump?", default=True)
                sniffer = NetworkSniffer(offline_pcap=pcap_path, show_payload=show_payload)
                sniffer.start()
            Prompt.ask("\nPress [bold yellow]Enter[/bold yellow] to return to the main menu")
            console.clear()
            continue

        if choice == "9":
            show_interfaces_table()
            Prompt.ask("\nPress [bold yellow]Enter[/bold yellow] to return to the main menu")
            console.clear()
            continue

        if choice == "8":
            console.print("\n[bold cyan]Launching Pure Python Raw Socket Sniffer...[/bold cyan]")
            count = IntPrompt.ask("Enter packet count limit (0 for unlimited)", default=10)
            sniffer = RawSocketSniffer()
            sniffer.start_sniffing(count=count)
            Prompt.ask("\nPress [bold yellow]Enter[/bold yellow] to return to the main menu")
            console.clear()
            continue

        # Scapy Engine Presets
        filter_map = {
            "1": None,
            "2": "tcp port 80 or tcp port 8080",
            "3": "udp port 53 or tcp port 53",
            "4": "tcp",
            "5": "udp",
            "6": "icmp",
        }

        bpf_filter = filter_map.get(choice)
        if choice == "7":
            bpf_filter = Prompt.ask("Enter custom BPF filter (e.g. 'tcp and port 443')")

        packet_count = IntPrompt.ask("Enter packet count limit (0 for continuous capture until Ctrl+C)", default=20)
        save_pcap = Confirm.ask("Do you want to save captured packets to a .pcap file (for Wireshark)?", default=True)

        output_pcap = None
        if save_pcap:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"captures/capture_{timestamp}.pcap"
            output_pcap = Prompt.ask("Enter output PCAP filename", default=default_name)

        show_payload = Confirm.ask("Display payload Hex/ASCII dump?", default=True)

        sniffer = NetworkSniffer(
            bpf_filter=bpf_filter,
            packet_count=packet_count,
            output_pcap=output_pcap,
            show_payload=show_payload,
        )
        sniffer.start()

        Prompt.ask("\nPress [bold yellow]Enter[/bold yellow] to return to the main menu")
        console.clear()


# ==============================================================================
# Command-Line Interface (CLI)
# ==============================================================================

def main():
    """CLI Argument parser and entrypoint."""
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1: Basic Network Sniffer & Protocol Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sniffer.py                              # Launch interactive menu
  python sniffer.py --demo                       # Run simulated demo (no admin required)
  python sniffer.py -r captures/demo.pcap        # Analyze an existing PCAP file
  python sniffer.py -c 10                        # Capture 10 packets on default interface
  python sniffer.py -f "icmp" -c 5               # Capture 5 ICMP (Ping) packets
  python sniffer.py -f "tcp port 80" -o web.pcap # Capture HTTP traffic and save to PCAP
  python sniffer.py -m raw -c 15                 # Run using low-level raw socket engine
  python sniffer.py --list-interfaces            # List available network adapters
        """
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on", default=None)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 = infinite)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter expression (e.g. 'tcp', 'udp port 53', 'icmp')", default=None)
    parser.add_argument("-o", "--output", help="Save captured packets to .pcap file path", default=None)
    parser.add_argument("-r", "--read-pcap", help="Read and dissect packets from an offline .pcap file", default=None)
    parser.add_argument("-m", "--mode", choices=["scapy", "raw"], help="Sniffer engine: 'scapy' (default) or 'raw'", default="scapy")
    parser.add_argument("--demo", action="store_true", help="Run multi-protocol simulated demo (no admin needed)")
    parser.add_argument("--no-payload", action="store_true", help="Do not display payload Hex/ASCII dump")
    parser.add_argument("--list-interfaces", action="store_true", help="List network interfaces and exit")
    parser.add_argument("--menu", action="store_true", help="Force interactive menu mode")

    args = parser.parse_args()

    if args.list_interfaces:
        display_banner()
        show_interfaces_table()
        sys.exit(0)

    # If launched with no arguments (or --menu), open interactive menu
    if len(sys.argv) == 1 or args.menu:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            console.print("\n[bold green]Exiting CodeAlpha Network Sniffer.[/bold green]")
            sys.exit(0)
        return

    display_banner()

    if args.demo:
        console.print("[bold green]Starting Demo Mode...[/bold green]")
        sniffer = NetworkSniffer(
            packet_count=args.count,
            output_pcap=args.output,
            show_payload=not args.no_payload,
        )
        sniffer.run_demo()
        return

    if args.read_pcap:
        if not os.path.exists(args.read_pcap):
            console.print(f"[bold red][!] PCAP file not found: {args.read_pcap}[/bold red]")
            sys.exit(1)
        sniffer = NetworkSniffer(
            offline_pcap=args.read_pcap,
            bpf_filter=args.filter,
            packet_count=args.count,
            output_pcap=args.output,
            show_payload=not args.no_payload,
        )
        sniffer.start()
        return

    if args.mode == "raw":
        console.print("[bold cyan]Starting Raw Socket Engine (Pure Python)...[/bold cyan]")
        sniffer = RawSocketSniffer()
        sniffer.start_sniffing(count=args.count)
    else:
        sniffer = NetworkSniffer(
            interface=args.interface,
            bpf_filter=args.filter,
            packet_count=args.count,
            output_pcap=args.output,
            show_payload=not args.no_payload,
        )
        sniffer.start()


if __name__ == "__main__":
    main()
