import asyncio
from mcp import ClientSession
from mcp.client.sse import sse_client

async def realtime_investigation():
    server_url = "http://127.0.0.1:800/sse"
    print("==================================================")
    print("🔍 AI Security Analyst: Real-time Incident Investigation")
    print("==================================================\n")
    
    async with sse_client(server_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            
            # Step 1: Fetch recent login logs using MCP Tool
            print("Step 1: Fetching recent login logs via MCP...")
            logs_res = await session.call_tool("get_login_logs", {"limit": 15})
            logs_data = eval(logs_res.content[0].text)
            
            # Count failed attempts per IP
            failed_attempts = {}
            for log in logs_data:
                if log.get("status") == "FAILED":
                    ip = log.get("ip_address")
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
                    
            print(f"-> Analyzed {len(logs_data)} recent logs.")
            print(f"-> Failed login attempt count per IP: {failed_attempts}\n")
            
            # Step 2: Detection Logic Check
            for ip, count in failed_attempts.items():
                if count >= 5:  # Brute force rule: 5+ failed attempts
                    print(f"🚨 THREAT DETECTED: Brute Force Attack from IP {ip} ({count} failed attempts)!")
                    
                    # Step 3: Check Threat Intel via MCP Tool
                    print(f"\nStep 3: Checking IP reputation for {ip} via MCP...")
                    rep_res = await session.call_tool("check_ip_reputation", {"ip_address": ip})
                    print(f"-> Threat Intel Result: {rep_res.content[0].text}\n")
                    
                    # Step 4: Execute Real-time Response via MCP Tools
                    print("Step 4: Triggering Automated Adaptive Response...")
                    
                    # 4a. Block IP
                    block_res = await session.call_tool("block_ip", {
                        "ip_address": ip, 
                        "reason": f"Automated response: Brute force attack detected ({count} failed logins)."
                    })
                    print(f"  [ACTION EXECUTED] {block_res.content[0].text}")
                    
                    # 4b. Lock User Account
                    lock_res = await session.call_tool("lock_user_account", {
                        "username": "admin", 
                        "reason": f"Compromise prevention due to brute force from {ip}"
                    })
                    print(f"  [ACTION EXECUTED] {lock_res.content[0].text}")
                    
                    # 4c. Generate Incident Report
                    report_res = await session.call_tool("generate_incident_report", {
                        "title": "Brute Force Attack Mitigation",
                        "severity": "CRITICAL",
                        "details": f"IP {ip} performed {count} failed login attempts against user 'admin'.",
                        "recommended_actions": "IP blocked, account locked, credentials reset required."
                    })
                    print(f"  [REPORT GENERATED] {report_res.content[0].text}\n")
                    
                    print("✅ Incident investigation and adaptive response complete!")

if __name__ == "__main__":
    asyncio.run(realtime_investigation())