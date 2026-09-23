import json
import os
import sqlite3
import subprocess
from typing import Dict, List, Optional
from fastmcp import FastMCP
from starlette.responses import HTMLResponse

# Initialize FastMCP Server
mcp = FastMCP("AI Security Analyst MCP Server")

# Dynamically resolve absolute path to security.db
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "database", "security.db")

def query_db(query: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def execute_db(query: str, params: tuple = ()):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query, params)
    conn.commit()
    conn.close()

# ==========================================
# WEB HOMEPAGE ROUTE (Serves http://127.0.0.1:800/)
# ==========================================

@mcp.custom_route("/", methods=["GET"])
async def homepage(request):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AI Security Analyst MCP Server</title>
        <style>
            body { font-family: monospace; background: #0f172a; color: #38bdf8; padding: 40px; }
            .card { background: #1e293b; padding: 20px; border-radius: 8px; max-width: 600px; margin: 0 auto; border: 1px solid #334155; }
            h1 { color: #f8fafc; font-size: 20px; }
            code { background: #0284c7; color: white; padding: 3px 6px; border-radius: 4px; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>🛡️ AI Security Analyst MCP Server</h1>
            <p>Server Status: <strong style="color: #4ade80;">ONLINE</strong></p>
            <p>SSE Endpoint: <code>http://127.0.0.1:800/sse</code></p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

# ==========================================
# MCP TOOLS FOR LOG RETRIEVAL
# ==========================================

@mcp.tool()
def get_login_logs(limit: int = 50) -> List[Dict]:
    """Retrieve recent login activity logs from the database."""
    return query_db("SELECT * FROM login_logs ORDER BY timestamp DESC LIMIT ?", (limit,))

@mcp.tool()
def get_firewall_logs(limit: int = 50) -> List[Dict]:
    """Retrieve recent network firewall logs."""
    return query_db("SELECT * FROM firewall_logs ORDER BY timestamp DESC LIMIT ?", (limit,))

@mcp.tool()
def get_network_logs(limit: int = 50) -> List[Dict]:
    """Retrieve general network traffic logs."""
    return query_db("SELECT * FROM network_logs ORDER BY timestamp DESC LIMIT ?", (limit,))

@mcp.tool()
def get_security_alerts(limit: int = 20) -> List[Dict]:
    """Retrieve existing security alerts."""
    return query_db("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))

# ==========================================
# MCP TOOLS FOR THREAT INTELLIGENCE
# ==========================================

@mcp.tool()
def check_ip_reputation(ip_address: str) -> Dict:
    """Check if an IP address is flagged as malicious in the threat database."""
    results = query_db("SELECT * FROM threat_db WHERE ip_address = ?", (ip_address,))
    if results:
        return results[0]
    return {"ip_address": ip_address, "reputation": "Clean", "score": 0}

@mcp.tool()
def detect_vpn(ip_address: str) -> Dict:
    """Check if an IP address belongs to a known VPN or Tor exit node."""
    results = query_db("SELECT * FROM threat_db WHERE ip_address = ?", (ip_address,))
    if results and results[0].get("is_vpn"):
        return {"ip_address": ip_address, "is_vpn": True, "type": results[0].get("node_type", "VPN")}
    return {"ip_address": ip_address, "is_vpn": False, "type": "Direct Traffic"}

# ==========================================
# MCP TOOLS FOR MITIGATION & RESPONSE
# ==========================================

@mcp.tool()
def block_ip(ip_address: str, reason: str) -> Dict:
    """Block a malicious IP address by adding it to the database blocked list."""
    execute_db(
        "INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, datetime('now'))",
        (ip_address, reason)
    )
    return {"status": "success", "message": f"IP {ip_address} has been blocked successfully in DB.", "reason": reason}

@mcp.tool()
def block_ip_windows_firewall(ip_address: str) -> Dict:
    """Execute a Windows Defender Firewall rule to block inbound traffic from a malicious IP address on the OS level."""
    rule_name = f"Block_Malicious_IP_{ip_address.replace('.', '_')}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
    
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        # Also register in DB for auditing
        execute_db(
            "INSERT INTO blocked_ips (ip_address, reason, blocked_at) VALUES (?, ?, datetime('now'))",
            (ip_address, "Windows Firewall Inbound Rule Executed")
        )
        return {"status": "success", "message": f"Windows Firewall rule created for {ip_address}.", "output": result.stdout.strip()}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "message": "Failed to create rule. Make sure server is running with Administrator privileges.", "error": e.stderr.strip()}

@mcp.tool()
def lock_user_account(username: str, reason: str) -> Dict:
    """Lock a user account that shows signs of compromise."""
    execute_db(
        "UPDATE users SET is_locked = 1 WHERE username = ?",
        (username,)
    )
    execute_db(
        "INSERT INTO user_actions (username, action, reason, timestamp) VALUES (?, 'LOCK_ACCOUNT', ?, datetime('now'))",
        (username, reason)
    )
    return {"status": "success", "message": f"Account for user '{username}' locked.", "reason": reason}

# ==========================================
# MCP TOOL FOR INCIDENT REPORTING
# ==========================================

@mcp.tool()
def generate_incident_report(title: str, severity: str, details: str, recommended_actions: str) -> Dict:
    """Generate a formal PDF incident report using ReportLab and save it to the reports folder."""
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    reports_dir = os.path.join(BASE_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    filename = os.path.join(reports_dir, f"incident_{title.replace(' ', '_')}.pdf")
    
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 750, f"INCIDENT REPORT: {title}")
    c.setFont("Helvetica", 12)
    c.drawString(100, 720, f"Severity Level: {severity}")
    c.drawString(100, 690, "Details:")
    c.drawString(120, 670, details[:80])
    c.drawString(100, 630, "Recommended Actions:")
    c.drawString(120, 610, recommended_actions[:80])
    c.save()
    
    execute_db(
        "INSERT INTO reports (title, severity, file_path, created_at) VALUES (?, ?, ?, datetime('now'))",
        (title, severity, filename)
    )
    
    return {"status": "success", "file_path": filename}

if __name__ == "__main__":
    mcp.run(transport="sse", host="127.0.0.1", port=8001)