import os
import json
import subprocess
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, "blocked_ips.json")


def ensure_data_dir():
    """Ensure data directory exists"""
    os.makedirs(DATA_DIR, exist_ok=True)


def block_ip(ip_address, threat_type="unknown"):
    """
    Primary function to neutralize a threat by blocking the source IP.
    
    FIXED: Added threat_type parameter for better logging
    FIXED: Better error handling and simulation mode
    """
    ensure_data_dir()
    
    try:
        # Check if we are on a Linux system with iptables
        if shutil.which("iptables"):
            # Check if rule already exists to avoid duplicates
            check_cmd = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(check_cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            
            if result.returncode != 0:
                # Rule doesn't exist, add it
                cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                subprocess.run(cmd, check=True, timeout=10)
                print(f"[firewall] LIVE: IP {ip_address} has been blocked via iptables (threat: {threat_type})")
            else:
                print(f"[firewall] IP {ip_address} already blocked, skipping")
        else:
            # Simulation mode for Windows/Mac users
            print(f"[firewall] SIMULATION: Would block {ip_address} for threat: {threat_type}")
        
        # After attempting the block, save the record
        save_to_database(ip_address, threat_type)

    except subprocess.TimeoutExpired:
        print(f"[firewall error] Timeout blocking {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"[firewall error] Command failed for {ip_address}: {e}")
    except Exception as e:
        print(f"[firewall error] Failed to process block for {ip_address}: {e}")


def save_to_database(ip_address, threat_type="unknown"):
    """
    Saves the blocked IP into the project's data folder.
    """
    try:
        blocked_ips = []
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                blocked_ips = json.load(f)
                if not isinstance(blocked_ips, list):
                    blocked_ips = []

        # Store as dict with timestamp for better tracking
        entry = {
            "ip": ip_address,
            "threat_type": threat_type,
            "timestamp": __import__('datetime').datetime.now().isoformat()
        }
        
        # Check if already blocked (by IP only)
        existing_ips = [b["ip"] if isinstance(b, dict) else b for b in blocked_ips]
        if ip_address not in existing_ips:
            blocked_ips.append(entry)

        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f, indent=4)
        print(f"[firewall] Database updated: {ip_address} added to blocked_ips.json")

    except Exception as e:
        print(f"[firewall error] Database write failed: {e}")


def unblock_ip(ip_address):
    """Utility function to unblock an IP (manual intervention)"""
    try:
        if shutil.which("iptables"):
            cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, check=True, timeout=10)
            print(f"[firewall] LIVE: IP {ip_address} has been unblocked")
            return True
    except Exception as e:
        print(f"[firewall error] Failed to unblock {ip_address}: {e}")
    return False


def list_blocked_ips():
    """Utility function to list currently blocked IPs"""
    try:
        if shutil.which("iptables"):
            cmd = ["sudo", "iptables", "-L", "INPUT", "-n"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            for line in result.stdout.split('\n'):
                if "DROP" in line and "all" in line:
                    parts = line.split()
                    for part in parts:
                        if '.' in part and len(part.split('.')) == 4:
                            print(f"  Blocked: {part}")
    except Exception as e:
        print(f"[firewall error] Failed to list blocked IPs: {e}")


if __name__ == "__main__":
    print("--- Firewall Module Test ---")
    test_ip = "192.168.1.100"
    block_ip(test_ip, "test_threat")
    print("\nBlocked IPs in database:")
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, 'r') as f:
            print(json.dumps(json.load(f), indent=2))