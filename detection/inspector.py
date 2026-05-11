import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def inspect(packet_dict, signature_engine, anomaly_engine):
    """
    Coordinates the inspection of a packet by passing it through 
    signature and anomaly detection modules.
    
    FIXED: Returns standardized threat dict or None
    """
    try:
        # FIXED: Skip if packet_dict is invalid
        if not packet_dict or not isinstance(packet_dict, dict):
            return None
        
        # 1. Check for known attack signatures
        sig_match = signature_engine(packet_dict)
        
        # 2. Check for unusual behavior
        is_anomaly, anomaly_details = anomaly_engine(packet_dict)
        
        # 3. Decision Logic - Signature threats take priority
        if sig_match:
            return {
                "src_ip": packet_dict.get("src_ip", "unknown"),
                "dst_ip": packet_dict.get("dst_ip", "unknown"),
                "type": sig_match.get("name", "UNKNOWN"),
                "severity": sig_match.get("severity", "MEDIUM"),
                "confidence": "STRONG",
                "matched_signature": sig_match.get("id", "UNKNOWN"),
                "details": f"Signature match: {sig_match.get('name', 'Unknown')} - Category: {sig_match.get('category', 'Unknown')}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "category": sig_match.get("category", "unknown")
            }
        
        elif is_anomaly:
            return {
                "src_ip": packet_dict.get("src_ip", "unknown"),
                "dst_ip": packet_dict.get("dst_ip", "unknown"),
                "type": "ANOMALY",
                "severity": "LOW",
                "confidence": "WEAK",
                "matched_signature": "NONE",
                "details": anomaly_details,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "category": "behavioral"
            }
            
        return None  # No threat detected
        
    except Exception as e:
        print(f"[inspector error] {e}")
        return None