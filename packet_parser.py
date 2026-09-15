"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
Module: packet_parser.py
Description: Robust packet parser, protocol decoder, and hex/ASCII payload visualizer.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
import string


# Protocol ID to human-readable name mapping
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

# Common ICMP Type mappings
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

# Common Well-Known Ports
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


@dataclass
class ParsedPacket:
    """Structured representation of dissected network packet."""
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
        # Hex representation (split into 8 bytes and 8 bytes for readability)
        hex_part1 = " ".join(f"{b:02x}" for b in chunk[:8])
        hex_part2 = " ".join(f"{b:02x}" for b in chunk[8:])
        hex_part = f"{hex_part1:<23}  {hex_part2:<23}".strip()

        # Printable ASCII representation
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


def parse_scapy_packet(pkt: Any, max_payload_dump: int = 128) -> ParsedPacket:
    """
    Parse a Scapy packet object into a standardized ParsedPacket dataclass.
    Handles Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, DNS, and HTTP payloads.
    """
    # Import scapy layers lazily to keep parser decoupled
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR
    from scapy.packet import Raw

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
            # TLS record content types: 22 is Handshake, 23 is Application Data
            if raw_bytes[0] == 0x16:
                parsed.extra_details["tls_record"] = "TLS Handshake"
            elif raw_bytes[0] == 0x17:
                parsed.extra_details["tls_record"] = "TLS Application Data"

    return parsed
