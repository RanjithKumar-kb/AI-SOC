import sys
import os
import asyncio

# Ensure project root is in system path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ai_agent.detection_logic import run_full_detection_audit
from database.models import SessionLocal, BlockedIP, Alert

async def run_security_agent(prompt: str = "Inspect system logs and mitigate threats.") -> str:
    """
    Main entry point for the AI Security Agent.
    Analyzes system logs, runs threat detection rules, executes auto-mitigations,
    and returns a summary report string.
    """
    # 1. Execute automated threat detection logic
    detection_results = run_full_detection_audit()
    
    brute_force_detected = detection_results.get("brute_force_detected", False)
    sqli_detected = detection_results.get("sqli_detected", False)
    flagged_ips = detection_results.get("flagged_ips", [])
    
    actions_taken = []
    
    # 2. Automated Adaptive Response Logic
    if flagged_ips:
        db = SessionLocal()
        for ip in flagged_ips:
            existing = db.query(BlockedIP).filter_by(ip_address=ip).first()
            if not existing:
                # Execute auto-block action
                block_record = BlockedIP(ip_address=ip, reason="Automated AI Agent Mitigation")
                db.add(block_record)
                
                # Log system alert
                alert_record = Alert(
                    title="Threat Automatically Blocked",
                    severity="CRITICAL",
                    message=f"IP {ip} was automatically blocked by AI Agent following detection."
                )
                db.add(alert_record)
                actions_taken.append(f"🔒 Automatically blocked IP: {ip}")
            else:
                actions_taken.append(f"ℹ️ IP {ip} is already blocked.")
        
        db.commit()
        db.close()
    
    # 3. Construct Agent Response Summary
    risk_level = "CRITICAL" if (brute_force_detected or sqli_detected) else "LOW"
    
    response_summary = f"""
🚨 **AI SOC Security Agent Analysis**
----------------------------------------
• **Brute Force Attack Detected:** {brute_force_detected}
• **SQL Injection Detected:** {sqli_detected}
• **Overall Threat Risk Level:** {risk_level}

**Mitigation Actions:**
"""
    if actions_taken:
        for action in actions_taken:
            response_summary += f"\n  {action}"
    else:
        response_summary += "\n  ✅ No active threats requiring automated blocking."
        
    return response_summary.strip()

# Allow standalone execution testing
if __name__ == "__main__":
    result = asyncio.run(run_security_agent("Run system audit"))
    print(result)