# run_all.ps1 - Master Launcher with Real-time Packet Sniffer
Write-Host "Launching AI Security Analyst Platform..." -ForegroundColor Green

# 1. Start FastMCP Server
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python mcp_server/server.py"

# 2. Start FastAPI Backend
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python backend/main.py"

# 3. Start Streamlit Frontend UI
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; streamlit run frontend/app.py"

# 4. Start Live Network Sniffer (Elevated as Administrator)
Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-Command", "cd '$PSScriptRoot'; python sniffer.py"

Write-Host "All services started!" -ForegroundColor Cyan
Write-Host "   - Backend API  : http://127.0.0.1:8000" -ForegroundColor Yellow
Write-Host "   - Frontend UI   : http://localhost:8501" -ForegroundColor Yellow
Write-Host "   - Live Sniffer  : Running in elevated terminal" -ForegroundColor Yellow