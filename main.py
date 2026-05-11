import os
import sys
import json
import signal
from colorama import Fore, Style, init

def banner():
    print(Fore.YELLOW + """
       d8888 888                                      888
      d88888 888                                      888
     d88P888 888                                      888
    d88P 888 888 88888b.d88b.   .d88b.  88888b.   .d88888
   d88P  888 888 888 "888 "88b d88""88b 888 "88b d88" 888
  d88P   888 888 888  888  888 888  888 888  888 888  888
 d8888888888 888 888  888  888 Y88..88P 888  888 Y88b 888
d88P     888 888 888  888  888  "Y88P"  888  888  "Y88888
"""+ Style.RESET_ALL)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from capture.sniffer import start_sniffing_thread
from detection.inspector import inspect
from detection.anomaly import anomaly_engine
from detection.signature import check_signatures
from response.enforcer import enforce
from response.alerter import alert
from response.event_logs import log_event
from response.firewall import block_ip


CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def load_config():
    """Load configuration from config.json"""
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        print("[ERROR] config.json not found!")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid config.json: {e}")
        sys.exit(1)


def signature_engine_wrapper(packet_dict):
    return check_signatures(packet_dict)

def notifier_func(threat):
    print(f"[notifier] Would send notification for {threat['src_ip']} - {threat['type']}")


def handle_threat(threat):
    if not threat:
        return
    enforce(threat, block_ip, alert, log_event, notifier_func)


def packet_handler(packet):
    global config
    
    if packet.get("dst_port") not in config["ports"]:
        return
    
    if packet.get("src_ip") in config["whitelist"]:
        return
    
    result = inspect(packet, signature_engine_wrapper, anomaly_engine)
    
    if result:
        handle_threat(result)


def signal_handler(sig, frame):
    print("\n[*] Shutting down NIDS...")
    sys.exit(0)


def ensure_directories():
    dirs = [
        os.path.join(BASE_DIR, "data"),
        os.path.join(BASE_DIR, "data", "logs"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def main():
    global config
    
    ensure_directories()
    
    config = load_config()
    print("\n")
    banner()
    print('='*60)
    print("Network Intrusion Detection System")
    print('='*60)
    print(f"[*] Mode: {config['mode']}")
    print(f"[*] Interface: {config['interface']}")
    print(f"[*] Monitoring ports: {config['ports']}")
    print(f"[*] Whitelisted IPs: {config['whitelist']}")
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print("\n[*] Starting packet sniffer...")
    start_sniffing_thread(packet_handler)
    
    print("[*] NIDS is active. Press Ctrl+C to stop.\n")
    
    try:
        while True:
            pass
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
