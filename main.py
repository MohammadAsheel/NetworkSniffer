"""
CodeAlpha Cybersecurity Internship - Task 1: Basic Network Sniffer
Module: main.py
Description: Interactive Command-Line Interface (CLI) for the Network Sniffer.
             Features interactive menu, arguments parsing, live packet dissection,
             and protocol analysis.
"""

import sys
import os
import argparse
import ctypes
import platform
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt, Confirm

from sniffer import NetworkSniffer, get_available_interfaces
from raw_socket_sniffer import RawSocketSniffer


# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console()


def is_admin() -> bool:
    """Check if the current process has administrative / root privileges."""
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


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
            # Multi-Protocol Demo Simulation
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
            # Offline PCAP File Analysis
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
            # Raw Socket Engine
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

        # Configure parameters
        packet_count = IntPrompt.ask("Enter packet count limit (0 for continuous capture until Ctrl+C)", default=20)
        save_pcap = Confirm.ask("Do you want to save captured packets to a .pcap file (for Wireshark)?", default=True)

        output_pcap = None
        if save_pcap:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"captures/capture_{timestamp}.pcap"
            output_pcap = Prompt.ask("Enter output PCAP filename", default=default_name)

        show_payload = Confirm.ask("Display payload Hex/ASCII dump?", default=True)

        # Run Scapy Sniffer
        sniffer = NetworkSniffer(
            bpf_filter=bpf_filter,
            packet_count=packet_count,
            output_pcap=output_pcap,
            show_payload=show_payload,
        )
        sniffer.start()

        Prompt.ask("\nPress [bold yellow]Enter[/bold yellow] to return to the main menu")
        console.clear()


def main():
    """CLI Argument parser and entrypoint."""
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1: Basic Network Sniffer & Protocol Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                              # Launch interactive menu
  python main.py --demo                       # Run simulated demo (no admin required)
  python main.py -r captures/demo.pcap        # Analyze an existing PCAP file
  python main.py -c 10                        # Capture 10 packets on default interface
  python main.py -f "icmp" -c 5               # Capture 5 ICMP (Ping) packets
  python main.py -f "tcp port 80" -o web.pcap # Capture HTTP traffic and save to PCAP
  python main.py -m raw -c 15                 # Run using low-level raw socket engine
  python main.py --list-interfaces            # List available network adapters
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

    # If --list-interfaces requested
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

    # CLI direct execution
    display_banner()

    # Demo mode
    if args.demo:
        console.print("[bold green]Starting Demo Mode...[/bold green]")
        sniffer = NetworkSniffer(
            packet_count=args.count,
            output_pcap=args.output,
            show_payload=not args.no_payload,
        )
        sniffer.run_demo()
        return

    # Offline PCAP mode
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
