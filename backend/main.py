import sys
import os
from typing import List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, status, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
import requests

# Ensure python can locate project root modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from database.models import SessionLocal, User, LoginLog, NetworkLog, BlockedIP, Alert
from ai_agent.agent import run_security_agent
from backend.routes import reports
from ai_agent.detection_logic import evaluate_brute_force, evaluate_sql_injection

app = FastAPI(
    title="AI SOC Analyst API",
    version="1.0.0",
    description="Backend REST API for real-time log ingestion, threat analysis, and automated security orchestration."
)

# Enable CORS for Streamlit frontend interaction
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include external reports router
app.include_router(reports.router)

# --- Database Dependency Injection ---

def get_db():
    """Yields a database session per request and guarantees proper cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Pydantic Data Schemas ---

class LoginLogCreate(BaseModel):
    username: str
    ip_address: str
    status: str  # E.g., "SUCCESS" or "FAILED"

class NetworkLogCreate(BaseModel):
    ip_address: str
    endpoint: str
    payload: str
    request_method: Optional[str] = "POST"

class AgentQuery(BaseModel):
    prompt: Optional[str] = "Inspect logs and mitigate threats."

class SOCStatsResponse(BaseModel):
    total_logins: int
    failed_logins: int
    blocked_ips: int
    active_alerts: int

# --- Root Endpoint ---

@app.get("/", tags=["System"])
def read_root():
    return {
        "status": "online",
        "message": "AI SOC Analyst Backend API is active.",
        "docs": "Visit http://127.0.0.1:8000/docs for interactive API documentation."
    }

# --- Real-Time Ingestion Endpoints ---

@app.post("/api/logs/login", status_code=status.HTTP_201_CREATED, tags=["Ingestion"])
def receive_login_log(log_data: LoginLogCreate, db: Session = Depends(get_db)):
    """Real-time log ingestion endpoint for user login events."""
    new_log = LoginLog(
        username=log_data.username,
        ip_address=log_data.ip_address,
        status=log_data.status,
        timestamp=datetime.utcnow()
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    return {"status": "success", "message": "Login event ingested", "log_id": new_log.id}

@app.post("/api/logs/network", status_code=status.HTTP_201_CREATED, tags=["Ingestion"])
def receive_network_log(log_data: NetworkLogCreate, db: Session = Depends(get_db)):
    """Real-time log ingestion endpoint for web payloads & network traffic."""
    method = log_data.request_method if log_data.request_method else "POST"
    
    new_log = NetworkLog(
        ip_address=log_data.ip_address,
        request_method=method,
        endpoint=log_data.endpoint,
        payload=log_data.payload,
        timestamp=datetime.utcnow()
    )
    db.add(new_log)
    db.commit()
    db.refresh(new_log)
    return {"status": "success", "message": "Network traffic event ingested", "log_id": new_log.id}

# --- SOC Dashboard Endpoints ---

@app.get("/api/stats", response_model=SOCStatsResponse, tags=["Dashboard"])
def get_soc_stats(db: Session = Depends(get_db)):
    """Fetches high-level metrics for the SOC Dashboard overview cards."""
    total_logins = db.query(LoginLog).count()
    failed_logins = db.query(LoginLog).filter_by(status="FAILED").count()
    blocked_ips = db.query(BlockedIP).count()
    active_alerts = db.query(Alert).count()
    return {
        "total_logins": total_logins,
        "failed_logins": failed_logins,
        "blocked_ips": blocked_ips,
        "active_alerts": active_alerts
    }

@app.get("/api/logs/login", tags=["Dashboard"])
def get_login_logs(db: Session = Depends(get_db)):
    """Retrieves all historical login event logs."""
    logs = db.query(LoginLog).order_by(LoginLog.timestamp.desc()).all()
    return [
        {
            "id": l.id, 
            "username": l.username, 
            "ip_address": l.ip_address, 
            "status": l.status, 
            "timestamp": str(l.timestamp)
        } 
        for l in logs
    ]

@app.get("/api/logs/network", tags=["Dashboard"])
def get_network_logs(db: Session = Depends(get_db)):
    """Retrieves all historical network payload traffic logs."""
    logs = db.query(NetworkLog).order_by(NetworkLog.timestamp.desc()).all()
    return [
        {
            "id": n.id, 
            "ip_address": n.ip_address, 
            "request_method": getattr(n, "request_method", "POST"),
            "endpoint": n.endpoint, 
            "payload": n.payload, 
            "timestamp": str(n.timestamp)
        } 
        for n in logs
    ]

@app.get("/api/blocked-ips", tags=["Dashboard"])
def get_blocked_ips(db: Session = Depends(get_db)):
    """Retrieves the list of currently blocked malicious IP addresses."""
    ips = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
    return [
        {
            "id": i.id, 
            "ip_address": i.ip_address, 
            "reason": i.reason, 
            "blocked_at": str(i.blocked_at)
        } 
        for i in ips
    ]


# --- AI Agent & Automated Mitigation Endpoint ---

@app.post("/api/agent/run", tags=["AI Agent"])
async def trigger_agent(query: Optional[AgentQuery] = None, db: Session = Depends(get_db)):
    """Unified endpoint to execute automated threat mitigation and run AI Agent analysis."""
    user_prompt = query.prompt if query and query.prompt else "Inspect logs and mitigate threats."
    
    try:
        # 1. Evaluate Rule Engine & Perform Automated Mitigations directly in DB
        login_logs = [{"status": l.status, "ip_address": l.ip_address} for l in db.query(LoginLog).all()]
        network_logs = [{"payload": n.payload, "ip_address": n.ip_address} for n in db.query(NetworkLog).all()]

        blocked_count = 0

        # Brute Force Mitigation
        bf_eval = evaluate_brute_force(login_logs)
        if bf_eval.get("attack_detected"):
            for ip in bf_eval.get("suspicious_ips", []):
                if not db.query(BlockedIP).filter_by(ip_address=ip).first():
                    db.add(BlockedIP(ip_address=ip, reason=f"Brute Force ({bf_eval.get('risk_level', 'CRITICAL')})"))
                    blocked_count += 1

        # SQL Injection Mitigation
        sqli_eval = evaluate_sql_injection(network_logs)
        if sqli_eval.get("attack_detected"):
            for ip in sqli_eval.get("flagged_ips", []):
                if not db.query(BlockedIP).filter_by(ip_address=ip).first():
                    db.add(BlockedIP(ip_address=ip, reason=f"SQL Injection ({sqli_eval.get('risk_level', 'CRITICAL')})"))
                    blocked_count += 1

        db.commit()

        # 2. Run LangChain Agent Response
        agent_response = await run_security_agent(user_prompt)

        return {
            "status": "success",
            "message": f"Audit complete. Newly blocked IPs: {blocked_count}",
            "response": agent_response,
            "brute_force": bf_eval,
            "sql_injection": sqli_eval
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Agent Execution Error: {str(e)}"
        )

# --- IP Intelligence / VPN Lookup Endpoint ---

@app.get("/api/ip-check/{ip_address}", tags=["Intelligence"])
def check_ip_intelligence(ip_address: str):
    """Fetches real-time GeoIP, ISP, and Proxy/VPN details for any IP address."""
    # Check for private or loopback subnets
    if ip_address.startswith(("127.", "192.168.", "10.", "172.16.")):
        return {
            "ip_address": ip_address,
            "is_vpn": False,
            "score": 0,
            "country": "Local Network",
            "isp": "Private Subnet"
        }

    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,isp,org,proxy,hosting,query"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data.get("status") != "success":
            return {
                "ip_address": ip_address,
                "is_vpn": False,
                "score": 0,
                "country": "Unknown",
                "isp": "Unknown"
            }
            
        is_vpn = data.get("proxy", False) or data.get("hosting", False)
        
        return {
            "ip_address": data.get("query", ip_address),
            "is_vpn": is_vpn,
            "score": 85 if is_vpn else 10,
            "country": data.get("country", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch IP details: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    # Change module path so uvicorn reloads correctly from any working directory
    uvicorn.run(app, host="127.0.0.1", port=8000)