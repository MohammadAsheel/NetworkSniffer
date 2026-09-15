"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
Module: raw_socket_sniffer.py
Description: Pure Python standard library raw socket sniffer using struct unpacking.
             Demonstrates low-level binary parsing of IP, TCP, UDP, and ICMP headers.
"""

import sys
import os
import socket
import struct
import platform
import time
from typing import Optional, Callable
from packet_parser import format_hex_ascii, IP_PROTOCOLS, ICMP_TYPES, PORT_SERVICES, parse_tcp_flags


def get_default_host_ip() -> str:
    """Retrieve the primary local IPv4 address connected to the default network."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Connecting to a public IP doesn't send packets but resolves local interface IP
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


class RawSocketSniffer:
    """
    Low-level raw socket packet sniffer using Python standard library (socket + struct).
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
                # On Windows, raw sockets must use AF_INET with SOCK_RAW and IPPROTO_IP
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                self.sock.bind((self.host_ip, 0))
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                # Enable promiscuous mode on Windows
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # On Linux/macOS, can use raw IP socket
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
        print(f"[*] Capturing packets... (Press Ctrl+C to stop)\n")

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
        tos = iph[1]
        total_len = iph[2]
        packet_id = iph[3]
        flags_offset = iph[4]
        ttl = iph[5]
        protocol_num = iph[6]
        checksum = iph[7]
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
            # TCP Header (20 bytes minimum)
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
            # UDP Header (8 bytes)
            udph = struct.unpack("!HHHH", transport_data[:8])
            src_port = udph[0]
            dst_port = udph[1]
            udp_len = udph[2]

            packet_info["src_port"] = src_port
            packet_info["dst_port"] = dst_port
            payload = transport_data[8:]
            packet_info["payload"] = payload
            packet_info["payload_len"] = len(payload)

        elif protocol_num == 1 and len(transport_data) >= 4:
            # ICMP Header (4 bytes minimum)
            icmph = struct.unpack("!BBH", transport_data[:4])
            icmp_type = icmph[0]
            icmp_code = icmph[1]
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


if __name__ == "__main__":
    count_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    sniffer = RawSocketSniffer()
    sniffer.start_sniffing(count=count_arg)
