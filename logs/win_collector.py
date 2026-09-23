# Save as: logs/win_collector.py
import time
import requests
import win32evtlog

BACKEND_URL = "http://127.0.0.1:8000/api/logs/login"
EVENT_ID_FAILED = 4625

def start_windows_log_listener():
    """Monitors local Windows Security Event logs and streams failed logins to FastAPI."""
    hand = win32evtlog.OpenEventLog(None, "Security")
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    print("🟢 Live Windows Security Log Collector active...")
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                if event.EventID == EVENT_ID_FAILED:
                    data = event.StringInserts
                    if data:
                        payload = {
                            "username": data[5] if len(data) > 5 else "Unknown",
                            "ip_address": data[19] if len(data) > 19 and data[19] not in ("-", "::1") else "127.0.0.1",
                            "status": "FAILED",
                            "source": "Windows_Event_Viewer"
                        }
                        try:
                            requests.post(BACKEND_URL, json=payload, timeout=2)
                            print(f"⚠️ Forwarded Event 4625 to Backend: {payload['username']} from {payload['ip_address']}")
                        except Exception as e:
                            print(f"❌ Could not post to backend: {e}")
        time.sleep(3)

if __name__ == "__main__":
    start_windows_log_listener()