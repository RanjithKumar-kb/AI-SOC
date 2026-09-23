from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "database", "security.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst")
    is_locked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class LoginLog(Base):
    __tablename__ = "login_logs"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False)
    ip_address = Column(String(45), nullable=False)
    status = Column(String(20), nullable=False)  # SUCCESS, FAILED
    user_agent = Column(String(255))
    location = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow)

class FirewallLog(Base):
    __tablename__ = "firewall_logs"
    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    port = Column(Integer, nullable=False)
    action = Column(String(20), nullable=False)  # ALLOW, BLOCK
    protocol = Column(String(10), default="TCP")
    timestamp = Column(DateTime, default=datetime.utcnow)

class NetworkLog(Base):
    __tablename__ = "network_logs"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False)
    request_method = Column(String(10), nullable=False)
    endpoint = Column(String(255), nullable=False)
    payload = Column(Text)  # May contain HTTP requests with SQL injection payloads
    timestamp = Column(DateTime, default=datetime.utcnow)

class ThreatDB(Base):
    __tablename__ = "threat_db"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), unique=True, nullable=False)
    reputation = Column(String(20), nullable=False)  # Malicious, Clean, Suspicious
    score = Column(Integer, default=0)
    is_vpn = Column(Boolean, default=False)
    node_type = Column(String(50))

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(45), nullable=False)
    reason = Column(String(255), nullable=False)
    blocked_at = Column(DateTime, default=datetime.utcnow)

class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=False)
    source_ip = Column(String(45))
    created_at = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    file_path = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)