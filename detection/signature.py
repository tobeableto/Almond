import os
import json
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# FIXED: Correct path to signatures.json
SIGNATURES_PATH = os.path.join(BASE_DIR, "data", "signatures.json")

def load_signatures():
    """
    Reads signatures.json from the data/ folder and returns the list of
    signature dicts. Called once at startup.
    """
    try:
        with open(SIGNATURES_PATH, "r") as f:
            raw = json.load(f)
        return raw.get("signatures", [])
    except FileNotFoundError:
        print(f"[signature error] Could not find {SIGNATURES_PATH}")
        print("           Please ensure data/signatures.json exists")
        return []
    except json.JSONDecodeError as e:
        print(f"[signature error] Invalid JSON in signatures.json: {e}")
        return []


# Load signatures once when the module is imported
SIGNATURES = load_signatures()


def check_signatures(packet_dict):
    """
    Receives a packet dict (produced by sniffer.py, passed in by inspector.py).
    Loops through every signature and checks if the packet's payload matches.
    
    Returns the FIRST matching signature dict if a match is found.
    Returns None if no signature matches.
    """
    try:
        # Pull the fields we will search inside
        payload = packet_dict.get("payload", "")
        direction = packet_dict.get("direction", "")
        
        # Also check HTTP parsed data if available
        http_data = packet_dict.get("http", {})
        combined_payload = payload
        
        # Add HTTP body and path for better detection
        if http_data.get("body"):
            combined_payload += " " + http_data["body"]
        if http_data.get("path"):
            combined_payload += " " + http_data["path"]
        if http_data.get("full"):
            combined_payload += " " + http_data["full"]

        # Guard: if the payload is not a string, convert it
        if not isinstance(combined_payload, str):
            combined_payload = str(combined_payload)

        for sig in SIGNATURES:
            # Direction filter
            sig_direction = sig.get("direction", "BOTH")
            if sig_direction != "BOTH" and sig_direction != direction:
                continue

            # Regex match
            pattern = sig.get("pattern", "")
            if not pattern:
                continue

            if re.search(pattern, combined_payload):
                return sig

        return None

    except Exception as e:
        print(f"[signature error] {e}")
        return None


if __name__ == "__main__":
    # Test code remains the same
    fake_packet = {
        "src_ip": "192.168.1.45",
        "dst_ip": "8.8.8.8",
        "src_port": 54231,
        "dst_port": 80,
        "protocol": "TCP",
        "payload": "' OR 1=1 --",
        "size": 512,
        "direction": "INBOUND",
        "timestamp": "2024-01-15 14:32:01",
        "http": {}
    }

    print("=== Signature Engine Test ===")
    print(f"Payload being tested: {fake_packet['payload']}\n")

    result = check_signatures(fake_packet)

    if result:
        print(f"[MATCH FOUND]")
        print(f"  Signature ID : {result['id']}")
        print(f"  Name         : {result['name']}")
        print(f"  Severity     : {result['severity']}")
        print(f"  Category     : {result['category']}")
    else:
        print("[NO MATCH] — packet appears clean")