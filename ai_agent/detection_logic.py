import re

def evaluate_brute_force(logs, threshold=5):
    """
    Analyzes authentication logs to detect brute-force login attempts.
    """
    ip_counts = {}
    failed_logs = [log for log in logs if log.get("status") == "FAILED"]

    for log in failed_logs:
        ip = log.get("ip_address")
        if ip:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    suspicious_ips = [ip for ip, count in ip_counts.items() if count >= threshold]
    attack_detected = len(suspicious_ips) > 0

    return {
        "attack_detected": attack_detected,
        "risk_level": "CRITICAL" if attack_detected else "LOW",
        "suspicious_ips": suspicious_ips,
        "failed_attempts": ip_counts
    }


def evaluate_sql_injection(logs):
    """
    Analyzes network request payloads for common SQL Injection patterns.
    """
    sqli_patterns = [
        r"SELECT.*FROM",
        r"UNION.*SELECT",
        r"OR\s+['\"]?1['\"]?\s*=\s*['\"]?1",
        r"DROP\s+TABLE",
        r"INSERT\s+INTO",
        r"--",
        r";"
    ]
    
    flagged_ips = set()
    matched_payloads = []

    for log in logs:
        payload = log.get("payload", "")
        ip = log.get("ip_address")
        
        if payload:
            for pattern in sqli_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    if ip:
                        flagged_ips.add(ip)
                    matched_payloads.append({"ip": ip, "payload": payload})
                    break

    attack_detected = len(flagged_ips) > 0

    return {
        "attack_detected": attack_detected,
        "risk_level": "CRITICAL" if attack_detected else "LOW",
        "flagged_ips": list(flagged_ips),
        "matched_payloads": matched_payloads
    }


def run_full_detection_audit(login_logs, network_logs):
    """
    Consolidated function expected by agent.py to run all rules in a single call.
    """
    bf_eval = evaluate_brute_force(login_logs)
    sqli_eval = evaluate_sql_injection(network_logs)
    
    return {
        "brute_force": bf_eval,
        "sql_injection": sqli_eval
    }