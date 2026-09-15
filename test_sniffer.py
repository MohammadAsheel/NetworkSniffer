"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
Module: test_sniffer.py
Description: Unit and integration tests for packet parsing, protocol dissection,
             hex/ASCII dump formatting, and PCAP file generation.
"""

import os
import unittest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw
from scapy.utils import wrpcap, rdpcap

from packet_parser import (
    format_hex_ascii,
    parse_scapy_packet,
    parse_tcp_flags,
    get_service_name,
    ParsedPacket,
)
from raw_socket_sniffer import RawSocketSniffer
from sniffer import NetworkSniffer, generate_demo_packets


class TestPacketParser(unittest.TestCase):
    """Test suite for packet dissection and payload rendering."""

    def test_format_hex_ascii_empty(self):
        """Verify empty byte sequence handling."""
        self.assertEqual(format_hex_ascii(b""), "")

    def test_format_hex_ascii_standard(self):
        """Verify standard hex and ASCII formatting."""
        data = b"Hello, CodeAlpha Network Sniffer!"
        formatted = format_hex_ascii(data, max_bytes=64)
        self.assertIn("0000", formatted)
        # Check for hex representation of 'Hello' -> 48 65 6c 6c 6f
        self.assertIn("48 65 6c 6c 6f", formatted)
        # Check for ASCII representation
        self.assertIn("Hello, CodeAlpha", formatted)

    def test_format_hex_ascii_truncation(self):
        """Verify truncation message when data exceeds max_bytes."""
        data = b"A" * 100
        formatted = format_hex_ascii(data, max_bytes=32)
        self.assertIn("truncated", formatted)

    def test_parse_tcp_packet(self):
        """Verify dissection of a synthetic TCP packet with flags and payload."""
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / \
              IP(src="192.168.1.50", dst="93.184.216.34", ttl=64) / \
              TCP(sport=54321, dport=80, flags="SA", seq=1000, ack=2000) / \
              Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")

        parsed = parse_scapy_packet(pkt)
        self.assertEqual(parsed.protocol, "HTTP")
        self.assertEqual(parsed.src_ip, "192.168.1.50")
        self.assertEqual(parsed.dst_ip, "93.184.216.34")
        self.assertEqual(parsed.src_port, 54321)
        self.assertEqual(parsed.dst_port, 80)
        self.assertEqual(parsed.service, "HTTP")
        self.assertEqual(parsed.ttl, 64)
        self.assertIn("SYN", parsed.tcp_flags)
        self.assertIn("ACK", parsed.tcp_flags)
        self.assertIsNotNone(parsed.http_info)
        self.assertIn("GET /index.html", parsed.http_info)
        self.assertGreater(parsed.payload_len, 0)
        self.assertIn("HTTP", parsed.payload_hex_ascii)

    def test_parse_udp_packet(self):
        """Verify dissection of a synthetic UDP packet."""
        pkt = Ether() / \
              IP(src="10.0.0.1", dst="10.0.0.2") / \
              UDP(sport=12345, dport=53) / \
              Raw(load=b"\x00\x01\x01\x00\x00\x01\x00\x00")

        parsed = parse_scapy_packet(pkt)
        self.assertEqual(parsed.protocol, "UDP")
        self.assertEqual(parsed.src_ip, "10.0.0.1")
        self.assertEqual(parsed.dst_ip, "10.0.0.2")
        self.assertEqual(parsed.src_port, 12345)
        self.assertEqual(parsed.dst_port, 53)
        self.assertEqual(parsed.service, "DNS")

    def test_parse_dns_packet(self):
        """Verify dissection of a synthetic DNS query packet."""
        pkt = Ether() / \
              IP(src="192.168.1.10", dst="8.8.8.8") / \
              UDP(sport=53000, dport=53) / \
              DNS(rd=1, qd=DNSQR(qname="codealpha.tech"))

        parsed = parse_scapy_packet(pkt)
        self.assertEqual(parsed.protocol, "DNS")
        self.assertEqual(parsed.dns_query, "codealpha.tech")
        self.assertEqual(parsed.extra_details.get("dns_type"), "Query")

    def test_parse_icmp_packet(self):
        """Verify dissection of a synthetic ICMP Ping request."""
        pkt = Ether() / \
              IP(src="192.168.1.1", dst="192.168.1.254") / \
              ICMP(type=8, code=0)

        parsed = parse_scapy_packet(pkt)
        self.assertEqual(parsed.protocol, "ICMP")
        self.assertIn("Echo Request", parsed.icmp_type)

    def test_parse_arp_packet(self):
        """Verify dissection of an ARP request packet."""
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / \
              ARP(op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", pdst="192.168.1.2")

        parsed = parse_scapy_packet(pkt)
        self.assertEqual(parsed.protocol, "ARP")
        self.assertEqual(parsed.src_ip, "192.168.1.1")
        self.assertEqual(parsed.dst_ip, "192.168.1.2")
        self.assertEqual(parsed.extra_details.get("arp_op"), "Request")

    def test_pcap_write_and_read(self):
        """Verify PCAP writing and reading integrity."""
        test_pcap = "test_output.pcap"
        packets = [
            Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(),
            Ether() / IP(src="3.3.3.3", dst="4.4.4.4") / UDP(sport=53, dport=53)
        ]
        try:
            wrpcap(test_pcap, packets)
            self.assertTrue(os.path.exists(test_pcap))
            read_pkts = rdpcap(test_pcap)
            self.assertEqual(len(read_pkts), 2)
            self.assertEqual(read_pkts[0][IP].src, "1.1.1.1")
            self.assertEqual(read_pkts[1][IP].src, "3.3.3.3")
        finally:
            if os.path.exists(test_pcap):
                os.remove(test_pcap)

    def test_raw_socket_struct_unpacking(self):
        """Verify raw socket parser dissects IPv4 + TCP byte streams accurately."""
        # Synthesize 20 bytes IPv4 header + 20 bytes TCP header + payload
        # IPv4: Version=4, IHL=5 (0x45), TOS=0, Len=44, ID=1, Flags=0, TTL=64, Proto=6 (TCP), Checksum=0,
        # Src=192.168.1.100, Dst=192.168.1.1
        ip_header = bytes([
            0x45, 0x00, 0x00, 0x2C,
            0x00, 0x01, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            192, 168, 1, 100,
            192, 168, 1, 1
        ])
        # TCP: Sport=8080 (0x1F90), Dport=80 (0x0050), Seq=12345, Ack=0, Offset=5 (0x50), Flags=0x02 (SYN),
        # Win=64240, Crc=0, Urg=0
        tcp_header = bytes([
            0x1F, 0x90, 0x00, 0x50,
            0x00, 0x00, 0x30, 0x39,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0xFA, 0xF0,
            0x00, 0x00, 0x00, 0x00
        ])
        payload = b"TEST"
        raw_packet_bytes = ip_header + tcp_header + payload

        sniffer = RawSocketSniffer()
        parsed = sniffer._parse_packet(raw_packet_bytes)

        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["src_ip"], "192.168.1.100")
        self.assertEqual(parsed["dst_ip"], "192.168.1.1")
        self.assertEqual(parsed["src_port"], 8080)
        self.assertEqual(parsed["dst_port"], 80)
        self.assertIn("SYN", parsed["tcp_flags"])
        self.assertEqual(parsed["payload"], b"TEST")

    def test_packet_display_labels(self):
        """Verify display format explicitly includes Packet count and IP Address labels."""
        import io
        from unittest.mock import patch
        sniffer = RawSocketSniffer()
        sniffer.packet_count = 1
        p = {
            "timestamp": "12:00:00",
            "protocol": "TCP",
            "src_ip": "192.168.1.100",
            "src_port": 8080,
            "dst_ip": "192.168.1.1",
            "dst_port": 80,
            "raw_len": 60,
            "tcp_flags": "SYN",
            "icmp_type": None,
            "payload_len": 0,
            "payload": b"",
        }
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            sniffer._display_packet(p)
            output = mock_stdout.getvalue()
            self.assertIn("Packet #1", output)
            self.assertIn("Source IP Address: 192.168.1.100:8080", output)
            self.assertIn("Destination IP Address: 192.168.1.1:80", output)

    def test_generate_demo_packets(self):
        """Verify synthetic multi-protocol demo packet generator."""
        pkts = generate_demo_packets()
        self.assertGreaterEqual(len(pkts), 10)

    def test_network_sniffer_demo_execution(self):
        """Verify executing demo mode parses all synthetic packets."""
        sniffer = NetworkSniffer(verbose=False)
        sniffer.run_demo(delay=0)
        self.assertGreaterEqual(sniffer.total_packets, 10)
        self.assertIn("TCP", sniffer.stats_protocols)
        self.assertIn("DNS", sniffer.stats_protocols)
        self.assertIn("ICMP", sniffer.stats_protocols)

    def test_network_sniffer_offline_pcap(self):
        """Verify offline PCAP analysis on demo.pcap."""
        pcap_path = "captures/demo.pcap"
        if os.path.exists(pcap_path):
            sniffer = NetworkSniffer(offline_pcap=pcap_path, verbose=False)
            sniffer.start()
            self.assertEqual(sniffer.total_packets, 10)
            self.assertIn("TCP", sniffer.stats_protocols)


if __name__ == "__main__":
    unittest.main()
