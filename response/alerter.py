import json
import urllib.request
import urllib.error
import os
import threading
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

with open(os.path.join(BASE_DIR, "config.json")) as f:
    config = json.load(f)

TERMINAL_ALERTS = config["alerts"]["terminal"]
WEBHOOK_URL = config["alerts"]["webhook_url"]

_last_webhook_time = {}
_webhook_lock = threading.Lock()


class Colors:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;208m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    GREEN  = "\033[92m"


SEVERITY_COLORS = {
    "LOW":      Colors.CYAN,
    "MEDIUM":   Colors.YELLOW,
    "HIGH":     Colors.ORANGE,
    "CRITICAL": Colors.RED
}

SEVERITY_LABELS = {
    "LOW":      "[ LOW      ]",
    "MEDIUM":   "[ MEDIUM   ]",
    "HIGH":     "[ HIGH     ]",
    "CRITICAL": "[ CRITICAL ]"
}


def format_terminal_alert(threat):
    severity = threat["severity"]
    color = SEVERITY_COLORS.get(severity, Colors.WHITE)
    label = SEVERITY_LABELS.get(severity, "[ UNKNOWN ]")
    line = "=" * 60

    return (
        f"\n{color}{Colors.BOLD}{line}{Colors.RESET}\n"
        f"{color}{Colors.BOLD}{label} {threat['type']}{Colors.RESET}\n"
        f"  {Colors.WHITE}From    :{Colors.RESET} {threat['src_ip']}\n"
        f"  {Colors.WHITE}To      :{Colors.RESET} {threat['dst_ip']}\n"
        f"  {Colors.WHITE}Details :{Colors.RESET} {threat['details']}\n"
        f"  {Colors.WHITE}Time    :{Colors.RESET} {threat['timestamp']}\n"
        f"  {Colors.WHITE}Match   :{Colors.RESET} {threat['matched_signature']}\n"
        f"{color}{Colors.BOLD}{line}{Colors.RESET}\n"
    )


def send_terminal_alert(threat):
    if not TERMINAL_ALERTS:
        return
    print(format_terminal_alert(threat))


def send_webhook_alert(threat):
    if not WEBHOOK_URL:
        return
    if threat["severity"] not in ["HIGH", "CRITICAL"]:
        return

    ip = threat.get("src_ip", "unknown")
    now = datetime.now().timestamp()

    with _webhook_lock:
        if now - _last_webhook_time.get(ip, 0) < 30:
            return
        _last_webhook_time[ip] = now

    message = {
        "content": (
            f"**ARCHANGEL ALERT — {threat['severity']}**\n"
            f"**Type:** {threat['type']}\n"
            f"**From:** {threat['src_ip']}\n"
            f"**Details:** {threat['details']}\n"
            f"**Time:** {threat['timestamp']}"
        )
    }

    try:
        data = json.dumps(message).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        urllib.request.urlopen(req, timeout=5)
        print(f"[alerter] webhook sent for {threat['src_ip']}")
    except Exception as e:
        print(f"[alerter error] {e}")


def alert(threat):
    send_terminal_alert(threat)
    thread = threading.Thread(
        target=send_webhook_alert,
        args=(threat,),
        daemon=True
    )
    thread.start()
