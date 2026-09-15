"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
Module: sniffer.py
Description: Main network sniffer engine using Scapy. Provides live packet capture,
             BPF filtering, rich console output, statistics tracking, and PCAP export.
"""

import os
import sys
import time
from collections import Counter
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

from scapy.all import sniff, wrpcap, conf, get_if_list, IFACES
from packet_parser import parse_scapy_packet, ParsedPacket, format_hex_ascii


console = Console()

PROTOCOL_COLORS = {
    "TCP": "cyan",
    "UDP": "green",
    "ICMP": "yellow",
    "ARP": "magenta",
    "DNS": "blue",
    "HTTP": "bright_red",
    "IPv6": "bright_magenta",
}


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
        # Fallback to simple list
        for iface_name in get_if_list():
            interfaces.append({
                "id": iface_name,
                "name": str(iface_name),
                "ip": "N/A",
                "mac": "N/A",
                "description": ""
            })
    return interfaces


def generate_demo_packets() -> List[Any]:
    """Generate diverse synthetic packets covering ARP, DNS, TCP Handshake, HTTP, ICMP, and TLS."""
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.packet import Raw

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
        proto_tag = f"[{color} bold]{p.protocol:<5}[/{color} bold]"

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
                "store": True,  # Keep packets in memory for PCAP writing and stats
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
