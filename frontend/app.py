import streamlit as st
import requests
import pandas as pd

API_URL = "http://127.0.0.1:8000/api"

st.set_page_config(
    page_title="AI SOC Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for SOC Badge Styling
st.markdown("""
<style>
    .badge-vpn { background-color: #ef4444; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-direct { background-color: #22c55e; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-suspicious { background-color: #f59e0b; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-normal { background-color: #3b82f6; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# --- Header ---
st.title("🛡️ AI SOC Security Operations Center")
st.markdown("Real-time Threat Monitoring | Behavior Analysis | Network & VPN Intelligence")

# --- Helper Functions ---
def fetch_data(endpoint: str):
    """Fetches JSON data from backend REST API with status and exception checking."""
    try:
        clean_endpoint = endpoint.lstrip("/")
        res = requests.get(f"{API_URL}/{clean_endpoint}", timeout=5)
        if res.status_code == 200:
            return res.json()
        elif res.status_code == 404:
            st.error(f"⚠️ Endpoint Not Found (404): {API_URL}/{clean_endpoint}")
        else:
            st.error(f"⚠️ API Error ({res.status_code}): {res.text}")
    except Exception as e:
        st.error(f"🚨 Connection Error: {e}")
    return None

def run_agent_query(prompt_text: str):
    try:
        res = requests.post(f"{API_URL}/agent/run", json={"prompt": prompt_text}, timeout=15)
        if res.status_code == 200:
            return res.json().get("response", "No output returned.")
        return f"⚠️ Backend returned status code {res.status_code}"
    except Exception as e:
        return f"🚨 Connection error: {e}"

def fetch_pdf_report():
    try:
        res = requests.get(f"{API_URL}/report/pdf", timeout=10)
        if res.status_code == 200:
            return res.content
    except Exception:
        return None
    return None

# --- Sidebar ---
st.sidebar.header("🕹️ Operations & Audits")

if st.sidebar.button("🚨 Run Full Security Audit", use_container_width=True):
    with st.spinner("AI Agent inspecting logs and running threat mitigation..."):
        audit_output = run_agent_query("Inspect all authentication and network logs. Block any detected threats.")
        st.sidebar.success("Audit Complete!")
        st.sidebar.text_area("Audit Summary", audit_output, height=250)
        st.rerun()

st.sidebar.divider()
st.sidebar.header("📄 Compliance & Reports")

pdf_bytes = fetch_pdf_report()
if pdf_bytes:
    st.sidebar.download_button(
        label="📥 Download Incident Report (PDF)",
        data=pdf_bytes,
        file_name="soc_incident_report.pdf",
        mime="application/pdf",
        use_container_width=True
    )
else:
    st.sidebar.warning("⚠️ Could not fetch PDF report from API.")

st.sidebar.divider()
st.sidebar.caption("SOC Status: Active 🟢")

# --- Overview Metrics ---
stats = fetch_data("stats")
if stats:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Login Logs", stats.get("total_logins", 0))
    col2.metric("Failed Attempts", stats.get("failed_logins", 0), delta_color="inverse")
    col3.metric("Blocked IP Entities", stats.get("blocked_ips", 0), delta="Active Rule")
    col4.metric("Active SOC Alerts", stats.get("active_alerts", 0))
else:
    st.error("⚠️ Unable to reach FastAPI backend. Verify `python backend/main.py` is running.")

st.divider()

# --- Main Dashboard Tabs ---
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 All Log Entries & Behavior", 
    "🌐 IP & VPN Intelligence", 
    "🚫 Blocked Threats", 
    "🤖 AI SOC Assistant"
])

# TAB 1: ALL LOGS & BEHAVIOR ANALYSIS
with tab1:
    st.subheader("Unified System Logs & Behavioral Classification")
    
    log_type = st.radio("Select Log View:", ["Login Activity Logs", "Network Traffic Logs", "Firewall Logs"], horizontal=True)
    
    if log_type == "Login Activity Logs":
        logs = fetch_data("logs/login")
        if logs:
            df = pd.DataFrame(logs)
            
            def analyze_login_behavior(row):
                status = str(row.get("status", "")).upper()
                source = str(row.get("source", ""))
                if status == "FAILED":
                    return "🚨 Suspicious (Failed Login)"
                elif "Windows" in source:
                    return "💻 OS Direct Logon"
                return "✅ Normal Activity"

            df["Behavior Analysis"] = df.apply(analyze_login_behavior, axis=1)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No login logs found.")

    elif log_type == "Network Traffic Logs":
        logs = fetch_data("logs/network")
        if logs:
            df = pd.DataFrame(logs)
            
            def analyze_network_behavior(row):
                payload = str(row.get("payload", "")).lower()
                if "select" in payload or "union" in payload or "or 1=1" in payload:
                    return "🚨 Malicious Payload (SQLi)"
                elif "script" in payload:
                    return "🚨 Malicious Payload (XSS)"
                return "🟢 Normal Web Traffic"

            df["Behavior Analysis"] = df.apply(analyze_network_behavior, axis=1)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No network logs found.")

    elif log_type == "Firewall Logs":
        logs = fetch_data("logs/firewall")
        if logs:
            df = pd.DataFrame(logs)
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("No firewall logs found.")

# TAB 2: IP REPUTATION & VPN ANALYSIS
with tab2:
    st.subheader("IP Address Intelligence & VPN/Proxy Detection")
    
    col_input, col_button = st.columns([3, 1])
    target_ip = col_input.text_input("Enter IP Address to Inspect:", value="185.177.125.67")
    
    if col_button.button("Inspect IP Address", use_container_width=True):
        ip_info = fetch_data(f"ip-check/{target_ip}")
        
        if ip_info and isinstance(ip_info, dict) and "detail" not in ip_info:
            c1, c2, c3 = st.columns(3)
            c1.metric("IP Address", ip_info.get("ip_address", target_ip))
            
            is_vpn = ip_info.get("is_vpn", False)
            c2.metric("Connection Type", "🔒 VPN / Proxy / Tor" if is_vpn else "🌐 Direct IP")
            
            score = ip_info.get("score", 0)
            c3.metric("Threat Score", f"{score} / 100", delta="High Risk" if score > 50 else "Safe", delta_color="inverse")
            
            st.divider()
            info_col1, info_col2 = st.columns(2)
            info_col1.info(f"📍 **Origin Country:** {ip_info.get('country', 'N/A')}")
            info_col2.info(f"🏢 **ISP / Host:** {ip_info.get('isp', 'N/A')}")
        else:
            st.warning(f"Could not retrieve threat details for IP: {target_ip}")

# TAB 3: BLOCKED THREATS
with tab3:
    st.subheader("Isolated Threat Entities & Firewall Rules")
    blocked_ips = fetch_data("blocked-ips")
    if blocked_ips:
        df_blocked = pd.DataFrame(blocked_ips)
        st.dataframe(df_blocked, use_container_width=True, hide_index=True)
    else:
        st.success("No IP addresses are currently blocked.")

# TAB 4: AI SOC ASSISTANT CHAT
with tab4:
    st.subheader("Interactive AI SOC Security Assistant")
    
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    for msg in st.session_state.chat_messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Ask SOC agent (e.g., 'Analyze recent failed logins and identify VPN IPs')..."):
        st.session_state.chat_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            with st.spinner("Analyzing log behavior..."):
                response = run_agent_query(prompt)
                st.markdown(response)
                st.session_state.chat_messages.append({"role": "assistant", "content": response})