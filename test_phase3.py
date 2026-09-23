import os
import sys
import asyncio

# Ensure parent path is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from database.db_setup import init_db
from database.seed_data import seed_database
from ai_agent.detection_logic import evaluate_brute_force, evaluate_sql_injection
from ai_agent.agent import run_security_agent
from database.models import SessionLocal, LoginLog, NetworkLog

async def run_combined_test():
    print("==================================================")
    print("🚀 RUNNING PHASE 3 INTEGRATION TEST")
    print("==================================================\n")

    # 1. Reset and Seed Database
    print("📦 Step 1: Refreshing Database & Seed Data...")
    init_db()
    seed_database()
    print("✅ Database ready.\n")

    # 2. Test Rule-Based Detection Engine Directly
    print("🔍 Step 2: Testing detection_logic.py directly...")
    db = SessionLocal()
    
    # Convert SQLAlchemy model objects to standard dicts
    login_logs = [{"status": l.status, "ip_address": l.ip_address} for l in db.query(LoginLog).all()]
    network_logs = [{"payload": n.payload, "ip_address": n.ip_address} for n in db.query(NetworkLog).all()]
    db.close()

    bf_result = evaluate_brute_force(login_logs)
    sqli_result = evaluate_sql_injection(network_logs)

    print(f"   • Brute Force Check : Attack Detected = {bf_result['attack_detected']} | Risk = {bf_result.get('risk_level', 'LOW')}")
    print(f"   • SQL Injection Check: Attack Detected = {sqli_result['attack_detected']} | Risk = {sqli_result.get('risk_level', 'LOW')}")
    print("✅ Rule Engine logic executed cleanly.\n")

    # 3. Test Full ReAct Agent Execution (Ollama + MCP Tools)
    print("🧠 Step 3: Executing ReAct Agent via agent.py...")
    test_query = (
        "Analyze recent login logs and network requests. "
        "If you discover a brute force attempt or SQL injection, "
        "block the malicious IP and explain what action you took."
    )
    
    try:
        agent_output = await run_security_agent(test_query)
        print("\n--- 🤖 AI Security Agent Output ---")
        print(agent_output)
        print("-----------------------------------")
        print("\n🎉 INTEGRATION TEST COMPLETED SUCCESSFULLY!")
    except Exception as e:
        print(f"\n❌ Agent execution error: {e}")

if __name__ == "__main__":
    asyncio.run(run_combined_test())