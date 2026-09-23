import os
import sqlite3
import time

# Resolve project base directory dynamically (works whether run from root or mcp_server/)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(CURRENT_DIR) == "mcp_server":
    BASE_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
else:
    BASE_DIR = CURRENT_DIR

# Define DB directory and file path
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "security.db")

# Ensure the database directory exists
os.makedirs(DB_DIR, exist_ok=True)

def simulate_brute_force():
    ATTACKER_IP = "192.168.1.100"
    TARGET_USER = "admin"
    
    print("🚀 Starting real-time Brute Force attack simulation...")
    print(f"📁 Target Database: {DB_PATH}\n")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Ensure login_logs table exists
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        ip_address TEXT,
        status TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    
    for i in range(1, 11):
        cursor.execute(
            "INSERT INTO login_logs (username, ip_address, status) VALUES (?, ?, 'FAILED')",
            (TARGET_USER, ATTACKER_IP)
        )
        conn.commit()
        print(f"  [LOG GENERATED] Failed login attempt #{i} for '{TARGET_USER}' from IP {ATTACKER_IP}")
        time.sleep(0.5)
        
    conn.close()
    print("\n⚠️ Attack complete! 10 failed logins recorded in database.")

if __name__ == "__main__":
    simulate_brute_force()