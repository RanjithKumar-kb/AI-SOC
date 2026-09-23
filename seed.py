from database.models import SessionLocal, LoginLog, NetworkLog

db = SessionLocal()

# Insert Brute Force logs (6 failed attempts)
for _ in range(6):
    db.add(LoginLog(username="admin", ip_address="185.220.101.5", status="FAILED"))

# Insert SQL Injection log
db.add(NetworkLog(
    ip_address="10.0.0.88",
    endpoint="/login",
    payload="' OR '1'='1' --",
    request_method="POST"
))

db.commit()
db.close()
print("Attack logs successfully seeded into database!")