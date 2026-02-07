#!/usr/bin/env python3
"""Starter template for the honeypot assignment."""

import socket
import threading
import logging
import os
import time
import paramiko 

from logger import HoneypotLogger

HOST_KEY = paramiko.RSAKey.generate(2048)
BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.3"
LOG_PATH = "/app/logs/honeypot.log"

logger = HoneypotLogger()

class SSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip, client_port):
        self.client_ip = client_ip
        self.client_port = client_port
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        logger.log_auth_attempt(
            ip=self.client_ip,
            port=self.client_port,
            username=username,
            password=password,
        )
        return paramiko.AUTH_SUCCESSFUL  # Always "succeeds"

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

def handle_client(client, addr):
    ip, port = addr
    start_time = time.time()

    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    transport.local_version = BANNER

    server = SSHServer(ip, port)

    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            return

        logger.log_connection(ip, port)

        channel.send(b"Welcome to Ubuntu 22.04 LTS\n")
        channel.send(b"$ ")

        while True:
            data = channel.recv(1024)
            if not data:
                break

            command = data.decode(errors="ignore").strip()
            logger.log_command(ip, command)

            if command.lower() in ("exit", "logout"):
                break

            channel.send(b"bash: command not found\n")
            channel.send(b"$ ")

    except Exception as e:
        logging.error(f"Session error: {e}")

    finally:
        duration = round(time.time() - start_time, 2)
        logger.log_disconnect(ip, duration)
        transport.close()


def run_honeypot():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 22))
    sock.listen(100)

    logging.info("SSH Honeypot listening on port 22")

    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()



if __name__ == "__main__":
    logger.setup()
    run_honeypot()
