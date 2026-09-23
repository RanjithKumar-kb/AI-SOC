import random
from datetime import datetime, timedelta
from models import SessionLocal, User, LoginLog, FirewallLog, NetworkLog, ThreatDB, Alert

def seed_database():
    db = SessionLocal()
    print("Seeding database with initial mock security data...")

    # 1. Users
    if not db.query(User).first():
        admin = User(username="admin", password_hash="$2b$12$eImiTXuWVxfM37uY4JANjO5E.5R25V3pZlGzP5w05sZ23", role="admin")
        analyst = User(username="analyst1", password_hash="$2b$12$eImiTXuWVxfM37uY4JANjO5E.5R25V3pZlGzP5w05sZ23", role="analyst")
        db.add_all([admin, analyst])

    # 2. Threat Intel IPs
    malicious_ips = [
        ThreatDB(ip_address="192.168.1.100", reputation="Malicious", score=90, is_vpn=True, node_type="Tor Exit Node"),
        ThreatDB(ip_address="10.0.0.88", reputation="Suspicious", score=65, is_vpn=False, node_type="Direct Traffic"),
        ThreatDB(ip_address="172.16.0.45", reputation="Clean", score=0, is_vpn=False, node_type="Direct Traffic")
    ]
    for threat in malicious_ips:
        if not db.query(ThreatDB).filter_by(ip_address=threat.ip_address).first():
            db.add(threat)

    # 3. Login Logs (Including Brute Force pattern from 192.168.1.100)
    for i in range(10):
        db.add(LoginLog(
            username="admin",
            ip_address="192.168.1.100",
            status="FAILED",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            location="Unknown",
            timestamp=datetime.utcnow() - timedelta(minutes=10 - i)
        ))
    
    # Successful login
    db.add(LoginLog(username="analyst1", ip_address="172.16.0.45", status="SUCCESS", location="USA"))

    # 4. Firewall Logs
    ports = [22, 80, 443, 8080, 3306]
    for i in range(15):
        db.add(FirewallLog(
            source_ip=f"192.168.1.{random.randint(2, 200)}",
            destination_ip="10.0.0.1",
            port=random.choice(ports),
            action=random.choice(["ALLOW", "BLOCK"]),
            protocol="TCP"
        ))

    # 5. Network Logs (HTTP requests with SQL Injection Payloads)
    db.add(NetworkLog(
        ip_address="10.0.0.88",
        request_method="POST",
        endpoint="/api/v1/login",
        payload="username=admin' OR '1'='1'--&password=foo"
    ))
    db.add(NetworkLog(
        ip_address="10.0.0.88",
        request_method="GET",
        endpoint="/products",
        payload="id=1 UNION SELECT null, username, password FROM users--"
    ))
    db.add(NetworkLog(
        ip_address="172.16.0.45",
        request_method="GET",
        endpoint="/dashboard",
        payload="token=xyz123"
    ))

    # 6. Initial Alerts
    db.add(Alert(
        title="Multiple Failed Login Attempts",
        severity="HIGH",
        description="10 failed login attempts detected from IP 192.168.1.100 within 10 minutes.",
        source_ip="192.168.1.100"
    ))

    db.commit()
    db.close()
    print("Database seeding completed successfully!")

if __name__ == "__main__":
    seed_database()