import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from scapy.all import sniff, IP, TCP, Raw
from database.models import SessionLocal, NetworkLog
from datetime import datetime

def process_packet(packet):
    # Only process IP and TCP packets with payloads
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        payload = str(packet[Raw].load)

        # Filter: Only log HTTP-like traffic or requests containing payload strings
        if "POST" in payload or "GET" in payload or "SELECT" in payload or "admin" in payload:
            print(f"⚡ Captured Traffic from {src_ip} -> Payload: {payload[:50]}...")
            
            db = SessionLocal()
            log_entry = NetworkLog(
                ip_address=src_ip,
                request_method="POST" if "POST" in payload else "GET",
                endpoint="/live_captured_traffic",
                payload=payload[:200],  # Save truncated payload
                timestamp=datetime.utcnow()
            )
            db.add(log_entry)
            db.commit()
            db.close()

if __name__ == "__main__":
    print("📡 Starting Live Network Traffic Sniffer (Run as Administrator)...")
    # Sniff on active network interface
    sniff(filter="ip", prn=process_packet, store=False)