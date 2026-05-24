import logging
import time
import threading
from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
from collections import deque, defaultdict

# ── App Setup ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
logging.getLogger('werkzeug').setLevel(logging.ERROR)

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_LOGS   = 2000
MAX_ALERTS = 500
WINDOW_SEC = 10        # sliding window for correlation
SCAN_THRESH      = 8   # unique ports from one IP → port scan
BRUTE_THRESH     = 6   # failed TCP SYN to same port → brute force
ICMP_FLOOD_THRESH= 20  # ICMP packets in window → flood
DNS_THRESH       = 30  # DNS queries in window → tunnelling hint

# ── Port Intelligence DB (no external deps) ───────────────────────────────────
PORT_DB = {
    # port : (severity, attack_type, description, mitre_id, recommendation)
    20:   ("HIGH",   "FTP Data",          "FTP data transfer — cleartext, easily sniffable",             "T1071.002", "Disable FTP; use SFTP/SCP"),
    21:   ("HIGH",   "FTP Control",       "FTP login detected — credentials sent in plaintext",           "T1078",     "Replace with SFTP (port 22); block port 21"),
    22:   ("MEDIUM", "SSH",               "SSH connection — possible brute-force or lateral movement",    "T1021.004", "Enforce key-based auth; limit login attempts"),
    23:   ("HIGH",   "Telnet",            "Telnet detected — unencrypted remote access, critical risk",   "T1021.004", "Disable Telnet immediately; use SSH"),
    25:   ("MEDIUM", "SMTP",              "SMTP mail server activity — watch for spam/phishing relay",    "T1566",     "Enforce authentication; block open relay"),
    53:   ("LOW",    "DNS",               "DNS query — normal unless high volume (DNS tunnelling)",       "T1071.004", "Monitor for high DNS volume; use DNSSEC"),
    80:   ("LOW",    "HTTP",              "Unencrypted HTTP — data exposed in transit",                   "T1071.001", "Enforce HTTPS; redirect all HTTP"),
    110:  ("MEDIUM", "POP3",              "POP3 email retrieval — often cleartext",                       "T1114",     "Use POP3S or switch to IMAP over TLS"),
    135:  ("HIGH",   "RPC/DCOM",          "Windows RPC — frequent attack vector for remote exploits",     "T1021.003", "Block externally; patch regularly"),
    139:  ("HIGH",   "NetBIOS",           "NetBIOS session — SMB over legacy protocol, worm risk",        "T1021.002", "Disable NetBIOS; block at perimeter"),
    143:  ("LOW",    "IMAP",              "IMAP mail access — check for cleartext mode",                  "T1114",     "Enforce STARTTLS/IMAPS (993)"),
    443:  ("LOW",    "HTTPS",             "Encrypted web traffic — normal",                               "",          "Ensure valid certificates"),
    445:  ("HIGH",   "SMB",               "SMB share access — EternalBlue/ransomware vector",             "T1021.002", "Patch MS17-010; block 445 externally; disable SMBv1"),
    1433: ("HIGH",   "MSSQL",             "Microsoft SQL Server — DB exposure risk",                      "T1190",     "Bind to localhost; use VPN for remote access"),
    3306: ("HIGH",   "MySQL",             "MySQL port exposed — possible unauthorised DB access",          "T1190",     "Bind to 127.0.0.1; use SSH tunnel"),
    3389: ("HIGH",   "RDP",               "RDP detected — BlueKeep/ransomware delivery vector",           "T1021.001", "Enable NLA; restrict with firewall; use VPN"),
    4444: ("HIGH",   "Metasploit Shell",  "Port 4444 — default Metasploit reverse shell",                 "T1059",     "Immediately investigate host; isolate if compromised"),
    5900: ("HIGH",   "VNC",               "VNC remote desktop — often unencrypted",                       "T1021.005", "Tunnel VNC over SSH; enforce strong password"),
    6667: ("HIGH",   "IRC/Botnet C2",     "IRC port — common botnet C&C channel",                         "T1071.003", "Block; investigate originating host immediately"),
    8080: ("LOW",    "HTTP Proxy",        "Alternate HTTP port — proxy or dev server",                    "T1071.001", "Ensure it's intentional; enforce auth"),
    8443: ("LOW",    "HTTPS Alt",         "Alternate HTTPS port",                                         "",          "Verify certificate validity"),
    9200: ("HIGH",   "Elasticsearch",     "Elasticsearch exposed — unauthenticated data access risk",     "T1190",     "Bind to localhost; add authentication plugin"),
    27017:("HIGH",   "MongoDB",           "MongoDB port exposed — no auth by default",                    "T1190",     "Enable auth; bind to 127.0.0.1"),
}

RISK_WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 1}

# ── In-Memory State ───────────────────────────────────────────────────────────
traffic_log  = deque(maxlen=MAX_LOGS)
alerts       = deque(maxlen=MAX_ALERTS)
blocked_ips  = set()          # manually blocked IPs (UI feature)
risk_score   = 0
start_time   = datetime.now()
lock         = threading.Lock()

# Sliding-window counters  { src_ip: { "ports": set(), "timestamps": [t,...] } }
ip_state     = defaultdict(lambda: {
    "ports":       set(),
    "syn_ports":   defaultdict(list),   # port → [timestamps]
    "icmp_times":  [],
    "dns_times":   [],
    "pkt_times":   [],
})

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP"}

# ── Helpers ───────────────────────────────────────────────────────────────────
def _now_ts():
    return datetime.now().strftime("%H:%M:%S")

def _now_f():
    return time.time()

def _prune(lst, window=WINDOW_SEC):
    cutoff = _now_f() - window
    while lst and lst[0] < cutoff:
        lst.pop(0)

def _update_risk(severity):
    global risk_score
    risk_score += RISK_WEIGHTS.get(severity, 0)

def _make_alert(severity, attack_type, src, dst, description, detail="", mitre="", recommendation=""):
    global risk_score
    _update_risk(severity)
    a = {
        "id":             len(alerts) + 1,
        "timestamp":      _now_ts(),
        "severity":       severity,
        "attack_type":    attack_type,
        "source":         src,
        "target":         dst,
        "description":    description,
        "detail":         detail,
        "mitre":          mitre,
        "recommendation": recommendation,
    }
    alerts.appendleft(a)
    return a

# ── Detection Engine ──────────────────────────────────────────────────────────
def _port_scan_check(src_ip, dst_ip, dst_port):
    """Detect horizontal port scan: 1 src → many ports on same dst."""
    st = ip_state[src_ip]
    st["ports"].add(dst_port)
    st["pkt_times"].append(_now_f())
    _prune(st["pkt_times"])

    if len(st["ports"]) >= SCAN_THRESH:
        port_list = sorted(st["ports"])
        st["ports"].clear()   # reset after alert to avoid spam
        _make_alert(
            "HIGH", "Port Scan",
            src=src_ip, dst=dst_ip,
            description=f"Port scan detected: {len(port_list)} unique ports probed",
            detail=f"Scanned ports include: {', '.join(map(str, port_list[:15]))}{'...' if len(port_list) > 15 else ''}. "
                   f"Pattern consistent with Nmap SYN scan or automated vulnerability scanner.",
            mitre="T1046",
            recommendation="Block source IP at firewall. Run 'netstat -an' to verify open ports. "
                           "Enable port-scan detection on perimeter IDS/IPS."
        )

def _brute_force_check(src_ip, dst_ip, dst_port, flags):
    """Detect brute force: many SYN to same port from same src."""
    if not (flags & 0x02):   # only SYN packets
        return
    st = ip_state[src_ip]
    syn_list = st["syn_ports"][dst_port]
    syn_list.append(_now_f())
    _prune(syn_list)

    if len(syn_list) >= BRUTE_THRESH:
        port_info = PORT_DB.get(dst_port, ("?", "Unknown", "", "", ""))
        service = port_info[1]
        syn_list.clear()
        _make_alert(
            "HIGH", "Brute Force",
            src=src_ip, dst=f"{dst_ip}:{dst_port}",
            description=f"Brute-force on {service} (port {dst_port}): {BRUTE_THRESH}+ SYN in {WINDOW_SEC}s",
            detail=f"Rapid repeated TCP SYN packets to port {dst_port} ({service}) indicate automated "
                   f"credential stuffing or password spraying. Rate: {len(syn_list)+ BRUTE_THRESH} attempts in {WINDOW_SEC}s window.",
            mitre="T1110",
            recommendation=f"Block {src_ip} immediately. Enable account lockout policy. "
                           f"Consider fail2ban or similar. Check auth logs for successful login."
        )

def _icmp_flood_check(src_ip, dst_ip):
    """Detect ICMP flood / ping flood."""
    st = ip_state[src_ip]
    st["icmp_times"].append(_now_f())
    _prune(st["icmp_times"])
    count = len(st["icmp_times"])

    if count >= ICMP_FLOOD_THRESH:
        st["icmp_times"].clear()
        _make_alert(
            "HIGH", "ICMP Flood",
            src=src_ip, dst=dst_ip,
            description=f"ICMP flood: {count}+ packets in {WINDOW_SEC}s",
            detail=f"High-volume ICMP echo requests from {src_ip} — possible ping flood DoS or Smurf attack. "
                   f"Rate: {count} packets/{WINDOW_SEC}s.",
            mitre="T1498.001",
            recommendation="Rate-limit ICMP at firewall (max 1/s). Block source IP. "
                           "Check if part of DDoS botnet by correlating with threat feeds."
        )

def _dns_tunnel_check(src_ip, dst_ip):
    """Detect DNS tunnelling via high-frequency queries."""
    st = ip_state[src_ip]
    st["dns_times"].append(_now_f())
    _prune(st["dns_times"])

    if len(st["dns_times"]) >= DNS_THRESH:
        st["dns_times"].clear()
        _make_alert(
            "MEDIUM", "DNS Tunnelling",
            src=src_ip, dst=dst_ip,
            description=f"Abnormal DNS query rate: {DNS_THRESH}+ queries in {WINDOW_SEC}s",
            detail=f"High-frequency DNS queries from {src_ip} may indicate DNS tunnelling — "
                   f"a technique used to exfiltrate data or bypass firewall inspection by encoding data in DNS queries.",
            mitre="T1071.004",
            recommendation="Inspect DNS payload size (>100 bytes per query is suspicious). "
                           "Enable DNS logging. Block at DNS firewall if confirmed tunnelling."
        )

# ── Packet Processor ──────────────────────────────────────────────────────────
def process_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        src_ip   = packet[IP].src
        dst_ip   = packet[IP].dst
        proto_n  = packet[IP].proto
        protocol = PROTO_MAP.get(proto_n, f"PROTO-{proto_n}")
        pkt_len  = len(packet)
        ts       = _now_ts()

        src_port = dst_port = "-"
        flags    = 0
        severity = "LOW"
        atk_type = "Normal"
        desc     = f"{protocol} Packet"
        detail   = ""
        mitre    = ""
        reco     = ""
        is_alert = False

        # ── TCP ───────────────────────────────────────────────────────────────
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags    = int(packet[TCP].flags)

            _port_scan_check(src_ip, dst_ip, dst_port)
            _brute_force_check(src_ip, dst_ip, dst_port, flags)

            if dst_port in PORT_DB:
                severity, atk_type, desc, mitre, reco = PORT_DB[dst_port]
                detail = (f"Connection to {atk_type} service on port {dst_port}. "
                          f"TCP flags: {int(flags):#04x}.")
                is_alert = severity in ("HIGH", "MEDIUM", "CRITICAL")

        # ── UDP ───────────────────────────────────────────────────────────────
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

            if dst_port == 53 or src_port == 53:
                _dns_tunnel_check(src_ip, dst_ip)
                desc = "DNS Query/Response"
                severity = "LOW"
            elif dst_port in PORT_DB:
                severity, atk_type, desc, mitre, reco = PORT_DB[dst_port]
                detail   = f"UDP packet to {atk_type} service on port {dst_port}."
                is_alert = severity in ("HIGH", "MEDIUM", "CRITICAL")

        # ── ICMP ──────────────────────────────────────────────────────────────
        elif packet.haslayer(ICMP):
            _icmp_flood_check(src_ip, dst_ip)
            icmp_type = packet[ICMP].type
            desc = {0: "ICMP Echo Reply", 8: "ICMP Echo Request (Ping)",
                    3: "ICMP Unreachable", 11: "ICMP TTL Exceeded"}.get(icmp_type, f"ICMP type {icmp_type}")
            severity = "LOW"

        # ── ARP ───────────────────────────────────────────────────────────────
        elif packet.haslayer(ARP):
            protocol = "ARP"
            desc     = "ARP — watch for spoofing"
            severity = "LOW"

        # Log packet
        with lock:
            traffic_log.appendleft({
                "id":        len(traffic_log) + 1,
                "timestamp": ts,
                "src":       src_ip,
                "sport":     src_port,
                "dst":       dst_ip,
                "dport":     dst_port,
                "protocol":  protocol,
                "len":       pkt_len,
                "info":      desc,
                "severity":  severity,
            })

        # Generate alert for port-based matches
        if is_alert and src_ip not in blocked_ips:
            with lock:
                _make_alert(severity, atk_type,
                            src=f"{src_ip}:{src_port}",
                            dst=f"{dst_ip}:{dst_port}",
                            description=desc,
                            detail=detail,
                            mitre=mitre,
                            recommendation=reco)

    except Exception:
        pass  # never crash the sniffer thread

# ── Sniffer Thread ────────────────────────────────────────────────────────────
def sniffer_thread():
    print("[-] Sniffer thread started (capturing all interfaces)...")
    sniff(prn=process_packet, store=False, filter="ip or arp")

# ── Flask Routes ──────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    with lock:
        high  = sum(1 for a in alerts if a['severity'] == 'HIGH')
        crit  = sum(1 for a in alerts if a['severity'] == 'CRITICAL')
        med   = sum(1 for a in alerts if a['severity'] == 'MEDIUM')
        uptime_sec = int((datetime.now() - start_time).total_seconds())
        return jsonify({
            "risk_score":      risk_score,
            "alert_count":     len(alerts),
            "traffic_count":   len(traffic_log),
            "high_severity":   high,
            "critical":        crit,
            "medium_severity": med,
            "uptime_sec":      uptime_sec,
            "blocked_ips":     len(blocked_ips),
        })

@app.route('/api/alerts')
def get_alerts():
    limit = int(request.args.get('limit', 50))
    with lock:
        return jsonify(list(alerts)[:limit])

@app.route('/api/traffic')
def get_traffic():
    limit = int(request.args.get('limit', 100))
    with lock:
        return jsonify(list(traffic_log)[:limit])

@app.route('/api/top_talkers')
def get_top_talkers():
    counts = defaultdict(int)
    with lock:
        for p in traffic_log:
            counts[p['src']] += 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{"ip": ip, "count": c} for ip, c in top])

@app.route('/api/block', methods=['POST'])
def block_ip():
    ip = request.json.get('ip', '').strip()
    if ip:
        blocked_ips.add(ip)
        return jsonify({"status": "blocked", "ip": ip})
    return jsonify({"status": "error"}), 400

@app.route('/api/blocked')
def get_blocked():
    return jsonify(list(blocked_ips))

@app.route('/api/clear_alerts', methods=['POST'])
def clear_alerts():
    global risk_score
    with lock:
        alerts.clear()
        risk_score = 0
    return jsonify({"status": "cleared"})

# ── Banner & Main ─────────────────────────────────────────────────────────────
def print_banner():
    print("\033[96m")
    print(r"""
███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
    """)
    print("      Network Traffic Monitoring & Detection | SOC Dashboard v2.0")
    print("                    Lightweight | No External APIs")
    print("\033[0m")
    print("-" * 70)

if __name__ == '__main__':
    print_banner()
    t = threading.Thread(target=sniffer_thread, daemon=True)
    t.start()
    print("[+] NetWatch v2.0 — Starting Web Server...")
    print("[+] Dashboard: http://127.0.0.1:5000  (local)")
    print("[+] Network  : http://0.0.0.0:5000    (LAN access)")
    app.run(debug=False, use_reloader=False, host='0.0.0.0', port=5000)
