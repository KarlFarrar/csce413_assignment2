#!/usr/bin/env python3
"""
Port Scanner - Starter Template for Students
Assignment 2: Network Security

This is a STARTER TEMPLATE to help you get started.
You should expand and improve upon this basic implementation.

TODO for students:
1. Implement multi-threading for faster scans
2. Add banner grabbing to detect services
3. Add support for CIDR notation (e.g., 192.168.1.0/24)
4. Add different scan types (SYN scan, UDP scan, etc.)
5. Add output formatting (JSON, CSV, etc.)
6. Implement timeout and error handling
7. Add progress indicators
8. Add service fingerprinting
"""

import socket
import sys
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


def grab_banner(sock):
    """Attempt to grab a service banner"""
    try: 
        sock.settimeout(1)
        return sock.recv(1024).decode(errors="ignore").strip()
    except Exception:
        return ""

def expand_targets(target):
    """
    Expands a target into a list of IP addresses.
    Supports single IPs, hostnames, and CIDR notation.
    """
    targets = []

    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            for ip in network.hosts():
                targets.append(str(ip))
        else:
            targets.append(target)
    except ValueError:
        # Hostname fallback
        targets.append(target)

    return targets

def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    start_time = time.time()
    # I want to try storing and returning the information for my use
    result = {
        "port": port, 
        "state": "closed",
        "time": None,
        "banner": ""
    }


    try:
        # TODO: Create a socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # TODO: Set timeout
            sock.settimeout(timeout)
            # TODO: Try to connect to target:port
            sock.connect((target, port))

            result["state"] = "open"

            banner = grab_banner(sock)
            result["banner"] = banner
            # TODO: Close the socket
            # TODO: Return True if connection successful
            

    except socket.timeout:
        result["state"] = "filtered (timeout)"
    except ConnectionRefusedError:
        result["state"] = "closed"
    except OSError:
        result["state"] = "error"
    
    result["time"] = round(time.time() - start_time, 4)
    return result


def scan_range(target, start_port, end_port, threads=300 ):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """
    open_ports = []
    results = []

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")
    print(f"[*] This may take a while...")
    print(f"[*] Using {threads}\n")

    # TODO: Implement the scanning logic
    # Hint: Loop through port range and call scan_port()
    # Hint: Consider using threading for better performance
    with ThreadPoolExecutor(max_workers=threads) as executer: 
        futures = {
            executer.submit(scan_port, target, port): port
            for port in range(start_port, end_port + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

            if result["state"] == "open":
                banner = f" | {result['banner']}" if result["banner"] else ""
                print(
                    f"[+] Port {result['port']:5d} OPEN "
                    f"({result['time']}s){banner}"
                )
    return sorted(results, key=lambda x: x["port"])


def main():
    """Main function"""
    # TODO: Parse command-line arguments
    # TODO: Validate inputs
    # TODO: Call scan_range()
    # TODO: Display results

    # Example usage (you should improve this):
    if len(sys.argv) < 4:
        print("Usage: python3 port_scanner_template.py <target> <start_port> <end_port>")
        print("Example: python3 port_scanner_template.py 172.20.0.10 1 1024")
        sys.exit(1)

    targets = expand_targets(sys.argv[1])
    try: 
        start_port = int(sys.argv[2]) if sys.argv[2] else 1024
        end_port = int(sys.argv[3])  # Scan first 1024 ports by default
    except ValueError:
        print("Ports must be integers")
        sys.exit(1)

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range")
        sys.exit(1)

    print(f"[*] Starting port scan")
    start_scan = time.time()

    all_results = {}

    for target in targets: 
        print(f"\n[*] Scanning host {target}")
        results = scan_range(target, start_port, end_port)
        all_results[target] = results
    

    duration = round(time.time() - start_scan, 2)

    print(f"\n[+] Scan complete!")
    print(f"[+] Scan time: {duration}s")

    open_ports = [r for r in results if r["state"] == "open"]

    print(f"[+] Found {len(open_ports)} open ports: \n")
    for r in open_ports:
        banner = f" | {r['banner']}" if r["banner"] else ""
        print(f"Port {r['port']:5d} OPEN{banner}")

if __name__ == "__main__":
    main()
