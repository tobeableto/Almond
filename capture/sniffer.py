import os
import json
import threading
from datetime import datetime
from urllib.parse import unquote_plus
from scapy.all import sniff, IP, TCP, UDP, Raw

# path setup - FIXED for consistent BASE_DIR
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# load config with error handling
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
except FileNotFoundError:
    print(f"[sniffer error] config.json not found at {CONFIG_PATH}")
    config = {"interface": "enp0s8", "ports": [80]}  # fallback
except json.JSONDecodeError as e:
    print(f"[sniffer error] Invalid config.json: {e}")
    config = {"interface": "enp0s8", "ports": [80]}

INTERFACE = config.get("interface", "enp0s8")
PORTS = config.get("ports", [80])


def parse_packet(packet):
    """
    receives a raw scapy packet
    converts it into a clean dict
    returns None if packet is not relevant
    """
    try:
        # ignore packets with no IP layer
        if not packet.haslayer(IP):
            return None

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        payload = ""

        # check if TCP
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        # check if UDP
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # extract raw payload if it exists
        if packet.haslayer(Raw):
            try:
                raw = packet[Raw].load.decode("utf-8", errors="ignore")
                payload = ''.join(c for c in raw if c.isprintable() or c in '\r\n')
            except Exception:
                payload = ""

        # determine direction - FIXED: Check both src and dst ports
        direction = None
        if dst_port in PORTS:
            direction = "INBOUND"
        elif src_port in PORTS:
            direction = "OUTBOUND"
        else:
            return None

        # FIXED: Also parse HTTP for richer data
        http_data = parse_http(payload) if payload else {}
        
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "payload": payload,
            "size": len(packet),
            "direction": direction,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "http": http_data  # FIXED: Include parsed HTTP data
        }

    except Exception as e:
        print(f"[sniffer error] {e}")
        return None


def parse_http(raw_payload):
    """
    parses raw HTTP payload into structured dict
    """
    try:
        if "\r\n\r\n" in raw_payload:
            header_section, body = raw_payload.split("\r\n\r\n", 1)
        else:
            header_section = ""
            body = raw_payload

        lines = header_section.split("\r\n")
        first_line = lines[0] if lines else ""
        parts = first_line.split(" ")
        method = parts[0] if len(parts) > 0 else ""
        path = parts[1] if len(parts) > 1 else ""

        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()

        decoded_body = unquote_plus(body)
        full_inspection = f"{path} {decoded_body} {str(headers)}"

        return {
            "method": method,
            "path": path,
            "headers": headers,
            "body": decoded_body,
            "raw_body": body,
            "full": full_inspection,
            "user_agent": headers.get("user-agent", "")
        }

    except Exception:
        return {
            "method": "",
            "path": "",
            "headers": {},
            "body": unquote_plus(raw_payload),
            "raw_body": raw_payload,
            "full": unquote_plus(raw_payload),
            "user_agent": ""
        }


def start_sniffing(packet_callback):
    """
    starts scapy sniff on configured interface
    calls packet_callback for every valid parsed packet
    runs forever
    """
    print(f"[*] Almond is watching on {INTERFACE}")
    print(f"[*] Monitoring ports: {PORTS}")

    def handle_packet(packet):
        parsed = parse_packet(packet)
        if parsed:
            # FIXED: Remove debug print or make it optional
            # print(f"[debug] {parsed['src_ip']} → {parsed['dst_port']} | {parsed.get('payload', '')[:50]}")
            packet_callback(parsed)

    try:
        sniff(
            iface=INTERFACE,
            prn=handle_packet,
            store=False
        )
    except PermissionError:
        print("[ERROR] Need root/sudo permissions to capture packets!")
        print("        Run: sudo python3 main.py")
    except Exception as e:
        print(f"[sniffer error] {e}")


def start_sniffing_thread(packet_callback):
    """
    runs sniffer in background thread
    so main.py stays free to do other things
    """
    thread = threading.Thread(
        target=start_sniffing,
        args=(packet_callback,),
        daemon=True
    )
    thread.start()
    return thread