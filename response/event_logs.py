import os
import json
import time
from datetime import datetime
from collections import defaultdict

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Load config with fallback
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    config = {"logging": {"log_dir": "data/logs/"}, "alerts": {"alert_cooldown_seconds": 30}}

LOG_DIR = os.path.join(BASE_DIR, config.get("logging", {}).get("log_dir", "data/logs/"))
LOG_COOLDOWN = config.get("alerts", {}).get("alert_cooldown_seconds", 30)

# Track last log time per IP
last_log_time = defaultdict(float)

# Make sure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)


def get_log_filename():
    """Generates today's log filename based on date"""
    today = datetime.now().strftime("%Y-%m-%d")
    return os.path.join(LOG_DIR, f"{today}.json")


def load_todays_log():
    """Loads today's log file if it exists, returns empty list if fresh day"""
    filename = get_log_filename()
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                return []
        except (json.JSONDecodeError, FileNotFoundError):
            return []
    return []


def get_action(severity):
    """Returns what action was taken based on severity"""
    actions = {
        "LOW": "LOGGED",
        "MEDIUM": "ALERTED",
        "HIGH": "BLOCKED",
        "CRITICAL": "BLOCKED + NOTIFIED"
    }
    return actions.get(severity, "LOGGED")


def log_event(threat):
    """Appends a threat event to today's log file with rate limiting per IP"""
    if not threat:
        return
    
    ip = threat.get("src_ip", "unknown")
    current_time = time.time()
    
    # Check cooldown
    if current_time - last_log_time[ip] < LOG_COOLDOWN:
        return
    
    last_log_time[ip] = current_time
    
    logs = load_todays_log()
    
    # Calculate next ID
    next_id = max([log.get("id", 0) for log in logs], default=0) + 1
    
    entry = {
        "id": next_id,
        "timestamp": threat.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "src_ip": threat.get("src_ip", "unknown"),
        "dst_ip": threat.get("dst_ip", "unknown"),
        "type": threat.get("type", "unknown"),
        "severity": threat.get("severity", "unknown"),
        "confidence": threat.get("confidence", "unknown"),
        "matched_signature": threat.get("matched_signature", "unknown"),
        "category": threat.get("category", "unknown"),
        "details": threat.get("details", ""),
        "action_taken": get_action(threat.get("severity", "LOW"))
    }
    
    logs.append(entry)
    
    # Write back to file
    try:
        with open(get_log_filename(), "w") as f:
            json.dump(logs, f, indent=4)
        print(f"[logger] Event logged — {entry['type']} from {entry['src_ip']} (Severity: {entry['severity']})")
    except Exception as e:
        print(f"[logger error] Failed to write log: {e}")


def get_todays_stats():
    """Returns summary of today's detections"""
    logs = load_todays_log()
    
    stats = {
        "total": len(logs),
        "low": 0,
        "medium": 0,
        "high": 0,
        "critical": 0,
        "blocked_ips": []
    }
    
    seen_ips = set()
    for entry in logs:
        severity = entry.get("severity", "").upper()
        if severity == "LOW":
            stats["low"] += 1
        elif severity == "MEDIUM":
            stats["medium"] += 1
        elif severity == "HIGH":
            stats["high"] += 1
        elif severity == "CRITICAL":
            stats["critical"] += 1
        
        action = entry.get("action_taken", "")
        if "BLOCKED" in action:
            ip = entry.get("src_ip", "")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                stats["blocked_ips"].append(ip)
    
    return stats


if __name__ == "__main__":
    # Test the logger
    test_threat = {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "type": "SQL Injection",
        "severity": "HIGH",
        "confidence": "STRONG",
        "matched_signature": "SIG001",
        "category": "sqli",
        "details": "Test injection detected",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    log_event(test_threat)
    print(f"Stats: {get_todays_stats()}")