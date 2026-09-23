import time
import sys
import requests

# Set target FastAPI server address
TARGET_SERVER = "http://127.0.0.1:8000"

def check_server_connection():
    """Verify backend server is online before running the simulation."""
    try:
        response = requests.get(f"{TARGET_SERVER}/", timeout=3)
        if response.status_code == 200:
            print("[+] Connected to FastAPI Backend server successfully.\n")
            return True
    except requests.exceptions.ConnectionError:
        print(f"[❌ ERROR] Unable to connect to backend server at {TARGET_SERVER}.")
        print("    Please ensure FastAPI is running via 'python backend/main.py'\n")
        sys.exit(1)

def simulate_brute_force_attack():
    """Simulate multiple rapid failed SSH/Web login attempts from a single IP."""
    print("--------------------------------------------------")
    print("[🔥 LIVE ATTACK] Initiating Brute-Force SSH/Web Login Attack...")
    print("--------------------------------------------------")
    target_ip = "192.168.1.100"
    
    for i in range(1, 7):
        payload = {
            "username": "admin",
            "ip_address": target_ip,
            "status": "FAILED"
        }
        try:
            res = requests.post(f"{TARGET_SERVER}/api/logs/login", json=payload, timeout=5)
            print(f"  └─ Attempt {i}: Sent failed login payload from {target_ip} (HTTP Status: {res.status_code})")
        except Exception as e:
            print(f"  └─ Attempt {i} Failed: {str(e)}")
        time.sleep(0.4)

def simulate_sql_injection():
    """Simulate a malicious web exploit payload (SQL Injection) in network logs."""
    print("\n--------------------------------------------------")
    print("[🔥 LIVE ATTACK] Initiating Web Exploit / SQL Injection Attack...")
    print("--------------------------------------------------")
    target_ip = "10.0.0.88"
    payload = {
        "ip_address": target_ip,
        "request_method": "POST",
        "endpoint": "/api/users/login",
        "payload": "username=admin' OR '1'='1'--&password=foo"
    }
    try:
        res = requests.post(f"{TARGET_SERVER}/api/logs/network", json=payload, timeout=5)
        print(f"  └─ Sent SQL Injection payload from {target_ip} (HTTP Status: {res.status_code})")
    except Exception as e:
        print(f"  └─ Failed to send SQL Injection payload: {str(e)}")

if __name__ == "__main__":
    print("==================================================")
    print("   🔴 REAL-TIME SECURITY ATTACK SIMULATION")
    print("==================================================")
    
    check_server_connection()
    simulate_brute_force_attack()
    time.sleep(1)
    simulate_sql_injection()
    
    print("\n==================================================")
    print("[🎉] Real-time attack logs delivered successfully!")
    print("     Check your Streamlit SOC Dashboard at http://localhost:8501")
    print("==================================================")