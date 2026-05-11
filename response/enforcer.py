import os
import json
import time
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load config with fallback
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    print("[enforcer] Warning: Could not load config.json, using defaults")
    config = {"whitelist": [], "mode": "monitor"}

WHITELIST = config.get("whitelist", [])
MODE = config.get("mode", "monitor")
ESCALATE_AFTER = 2
ESCALATE_WINDOW = 60

# Tracks recent hits per IP for escalation
ip_hit_history = defaultdict(list)

severity_order = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4
}


def escalate_if_needed(threat):
    """
    If same IP triggers multiple threats within the escalation window,
    bump severity up.
    """
    ip = threat.get("src_ip", "unknown")
    now = time.time()

    ip_hit_history[ip].append(now)

    # Remove hits outside window
    ip_hit_history[ip] = [
        t for t in ip_hit_history[ip]
        if now - t <= ESCALATE_WINDOW
    ]

    # Escalate if too many hits
    if len(ip_hit_history[ip]) >= ESCALATE_AFTER:
        current_level = severity_order.get(threat.get("severity", "LOW"), 1)
        if current_level < 4:
            levels = {v: k for k, v in severity_order.items()}
            new_severity = levels.get(current_level + 1, "CRITICAL")
            threat["severity"] = new_severity
            threat["details"] = threat.get("details", "") + (
                f" | ESCALATED — {len(ip_hit_history[ip])} hits in {ESCALATE_WINDOW}s"
            )

    return threat


def enforce(threat, firewall_func, alerter_func, logger_func, notifier_func):
    """
    Receives threat from inspector, decides what to do based on severity.
    
    FIXED: Added proper error handling and null checks
    """
    if not threat or not isinstance(threat, dict):
        print("[enforcer] Invalid threat received")
        return
    
    # Never touch whitelisted IPs
    src_ip = threat.get("src_ip", "")
    if src_ip in WHITELIST:
        print(f"[enforcer] {src_ip} is whitelisted — skipping")
        return

    # Check escalation
    threat = escalate_if_needed(threat)
    severity = threat.get("severity", "LOW")

    # Monitor mode — never block, only log and alert
    if MODE == "monitor":
        if logger_func:
            logger_func(threat)
        if severity in ["MEDIUM", "HIGH", "CRITICAL"] and alerter_func:
            alerter_func(threat)
        return

    # Enforce mode - take action based on severity
    if severity == "LOW":
        if logger_func:
            logger_func(threat)

    elif severity == "MEDIUM":
        if logger_func:
            logger_func(threat)
        if alerter_func:
            alerter_func(threat)

    elif severity == "HIGH":
        if logger_func:
            logger_func(threat)
        if alerter_func:
            alerter_func(threat)
        if firewall_func:
            firewall_func(src_ip, threat.get("type", "unknown"))

    elif severity == "CRITICAL":
        if logger_func:
            logger_func(threat)
        if alerter_func:
            alerter_func(threat)
        if firewall_func:
            firewall_func(src_ip, threat.get("type", "unknown"))
        if notifier_func:
            notifier_func(threat)