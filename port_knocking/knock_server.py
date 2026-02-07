#!/usr/bin/env python3
"""Starter template for the port knocking server."""

import select 
import argparse
import logging
import socket
import time
import subprocess
from collections import defaultdict 

DEFAULT_KNOCK_SEQUENCE = [1234, 5678, 9012]
DEFAULT_PROTECTED_PORT = 2222
DEFAULT_SEQUENCE_WINDOW = 10.0


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )

def run_cmd(cmd):
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 


def open_protected_port(protected_port):
    """Open the protected port using firewall rules."""
    # TODO: Use iptables/nftables to allow access to protected_port.
    logging.info("Opening protected port %s", protected_port)

    run_cmd([
        "iptables", "-I", "INPUT", "-p", "tcp",
        "--dport", str(protected_port), "-j", "ACCEPT"
    ])


def close_protected_port(protected_port):
    """Close the protected port using firewall rules."""
    # TODO: Remove firewall rules for protected_port.
    logging.info("Closing protected port %s", protected_port)
    run_cmd([
        "iptables", "-D", "INPUT", "-p", "tcp",
        "--dport", str(protected_port), "-j", "ACCEPT"
    ])

def block_protected_port(port):
    logging.info("Blocking protected port %d", port)
    run_cmd([
        "iptables", "-I", "INPUT", "-p", "tcp",
        "--dport", str(port), "-j", "DROP"
    ])

def reset_firewall(port):
    # Remove all ACCEPT rules for the port
    while True:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            break

    # Remove all DROP rules for the port
    while True:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode != 0:
            break

def listen_on_port(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen()
    s.settimeout(1.0)
    return s

def listen_for_knocks(sequence, window_seconds, protected_port):
    """Listen for knock sequence and open the protected port."""
    logger = logging.getLogger("KnockServer")
    logger.info("Listening for knocks: %s", sequence)
    logger.info("Protected port: %s", protected_port)

    # TODO: Create UDP or TCP listeners for each knock port.
    sockets = {p: listen_on_port(p) for p in sequence}
    # TODO: Track each source IP and its progress through the sequence.
    progress = defaultdict(lambda: {"index": 0, "start": None})
    # TODO: Enforce timing window per sequence.
    # TODO: On correct sequence, call open_protected_port().
    # TODO: On incorrect sequence, reset progress. 
    while True:
        readable, _, _ = select.select(sockets.values(), [], [], 1.0)

        for sock in readable:
            port = next(p for p, s in sockets.items() if s == sock)
            conn, addr = sock.accept()
            src_ip = addr[0]
            conn.close()

            state = progress[src_ip]
            now = time.time()

            if state["index"] == 0:
                state["start"] = now

            if now - state["start"] > window_seconds:
                logging.info("[%s] Sequence timeout", src_ip)
                progress[src_ip] = {"index": 0, "start": None}
                continue

            expected_port = sequence[state["index"]]

            if port == expected_port:
                state["index"] += 1
                logging.info("[%s] Correct knock %d (%d/%d)",
                            src_ip, port, state["index"], len(sequence))

                if state["index"] == len(sequence):
                    logging.info("[%s] Sequence complete!", src_ip)
                    open_protected_port(protected_port)
                    progress[src_ip] = {"index": 0, "start": None}
            else:
                logging.info("[%s] Wrong knock %d — resetting", src_ip, port)
                progress[src_ip] = {"index": 0, "start": None}

        
def parse_args():
    parser = argparse.ArgumentParser(description="Port knocking server starter")
    parser.add_argument(
        "--sequence",
        default=",".join(str(port) for port in DEFAULT_KNOCK_SEQUENCE),
        help="Comma-separated knock ports",
    )
    parser.add_argument(
        "--protected-port",
        type=int,
        default=DEFAULT_PROTECTED_PORT,
        help="Protected service port",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=DEFAULT_SEQUENCE_WINDOW,
        help="Seconds allowed to complete the sequence",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging()

    try:
        sequence = [int(port) for port in args.sequence.split(",")]
    except ValueError:
        raise SystemExit("Invalid sequence. Use comma-separated integers.")

    reset_firewall(args.protected_port)
    block_protected_port(args.protected_port)
    listen_for_knocks(sequence, args.window, args.protected_port)


if __name__ == "__main__":
    main()
