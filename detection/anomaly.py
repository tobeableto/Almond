import time
import os
from collections import defaultdict

# Files for logging and evidence
EVIDENCE_FILE = "anomaly_report.txt"

# Thresholds - These could also be pulled from config.json if passed in
MAX_PACKET_SIZE = 1600  # Threshold for unusual packet size[cite: 1]
VOLUME_THRESHOLD = 100  # Max packets per IP in a window[cite: 1]
WINDOW_SECONDS = 60     # Time window for volume and brute force tracking
BRUTE_FORCE_THRESHOLD = 10  # Number of "unauthorized" or "login" attempts

# State tracking for behavioral analysis
class TrafficTracker:
    def __init__(self):
        # Format: {ip: [timestamp1, timestamp2, ...]}
        self.packet_times = defaultdict(list)
        self.auth_attempts = defaultdict(list)

    def clean_old_data(self, ip, now):
        """Removes timestamps outside the current tracking window."""
        self.packet_times[ip] = [t for t in self.packet_times[ip] if now - t < WINDOW_SECONDS]
        self.auth_attempts[ip] = [t for t in self.auth_attempts[ip] if now - t < WINDOW_SECONDS]

tracker = TrafficTracker()

def anomaly_engine(packet_dict: dict) -> tuple[bool, str]:
    if not packet_dict or not isinstance(packet_dict, dict):
        return False, ""

    src_ip = packet_dict.get("src_ip", "unknown")
    packet_size = packet_dict.get("size", 0)
    now = time.time()

    findings = []

    # 1. Unusual Packet Size
    if packet_size > MAX_PACKET_SIZE:
        findings.append(f"Unusual packet size: {packet_size} bytes (limit: {MAX_PACKET_SIZE})")

    # 2. High Packet Volume (DoS/Scan behaviour)
    tracker.clean_old_data(src_ip, now)
    tracker.packet_times[src_ip].append(now)

    if len(tracker.packet_times[src_ip]) > VOLUME_THRESHOLD:
        findings.append(f"High packet volume: {len(tracker.packet_times[src_ip])} pkts/{WINDOW_SECONDS}s")

    if findings:
        description = "; ".join(findings)
        _write_evidence(src_ip, description)
        return True, description

    return False, ""
def _write_evidence(ip, description):
    """Logs the anomaly to the evidence file[cite: 7]."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] IP: {ip} | ANOMALY: {description}\n"
    print(f"[anomaly] {entry.strip()}")
    try:
        with open(EVIDENCE_FILE, "a") as f:
            f.write(entry)
    except OSError as e:
        print(f"[anomaly error] Could not write evidence: {e}")