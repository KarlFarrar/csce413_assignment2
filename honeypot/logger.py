import logging
import os
import time
from collections import defaultdict

LOG_FILE = "/app/logs/honeypot.log"


class HoneypotLogger:
    def __init__(self):
        self.failed_attempts = defaultdict(int)

    def setup(self):
        os.makedirs("/app/logs", exist_ok=True)
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(message)s",
            handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
        )

    def log_connection(self, ip, port):
        logging.info(f"Connection from {ip}:{port}")

    def log_auth_attempt(self, ip, port, username, password):
        logging.info(
            f"AUTH attempt from {ip}:{port} username='{username}' password='{password}'"
        )
        self.failed_attempts[ip] += 1

        if self.failed_attempts[ip] >= 5:
            logging.warning(f"ALERT: Possible brute-force from {ip}")

    def log_command(self, ip, command):
        logging.info(f"COMMAND from {ip}: {command}")

    def log_disconnect(self, ip, duration):
        logging.info(f"Disconnected {ip} after {duration}s")