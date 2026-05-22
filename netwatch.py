import logging
from flask import Flask, render_template, jsonify, request
from scapy.all import sniff, IP, TCP, UDP
import threading
import time
from datetime import datetime
from collections import deque, defaultdict

# --- Configuration & State ---
app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)  # Silence Flask logs

# In-memory storage
MAX_LOGS = 1000
traffic_log = deque(maxlen=MAX_LOGS)
alerts = deque(maxlen=MAX_LOGS)
risk_score = 0
start_time = datetime.now()

# Protocol Map
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Suspicious Ports & Signatures (Simulated Rule Set)
SUSPICIOUS_PORTS = {
    21: "FTP (High Risk)",
    22: "SSH (Medium Risk)",
    23: "Telnet (High Risk)",
    445: "SMB (High Risk)",
    3389: "RDP (Medium Risk)"
}

RISK_WEIGHTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 1
}

# Track recent activity for correlation (simple port scan detection)
ip_connection_count = defaultdict(lambda: defaultdict(int))
last_cleanup = time.time()

def calculate_severity(port, protocol):
    if port in SUSPICIOUS_PORTS:
        risk = SUSPICIOUS_PORTS[port]
        if "High" in risk:
            return "HIGH", risk
        elif "Medium" in risk:
            return "MEDIUM", risk
    return "LOW", "Standard Traffic"

def print_banner():
    # ANSI Cyan color for the banner
    print("\033[96m")
    print(r"""
███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗██████╗ ██╗  ██╗
████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔═══╝ ██║  ██║
██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ██████╗ ██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝
    """)
    print("      Network Traffic Monitoring & Detection | SOC Dashboard")
    print("                    v1.0 - Ready for Action")
    print("\033[0m")
    print("-" * 70)

def update_risk_score(severity):
    global risk_score
    risk_score += RISK_WEIGHTS.get(severity, 0)
    # Decay logic could go here, for now strictly cumulative for demo

def process_packet(packet):
    global risk_score, last_cleanup
    
    if not packet.haslayer(IP):
        return

    timestamp = datetime.now().strftime("%H:%M:%S")
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    proto_num = packet[IP].proto
    protocol = PROTO_MAP.get(proto_num, "OTHER")
    length = len(packet)

    src_port = "-"
    dst_port = "-"
    flags = ""
    
    severity = "LOW"
    description = "Normal Traffic"

    # Extract Ports and Analyze
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        
        # Check destination port for rules
        sev, desc = calculate_severity(dst_port, "TCP")
        if sev != "LOW":
            severity = sev
            description = desc

        # Correlation: Port Scan Detection (Simulated)
        # If one source connects to > 5 ports on same dest in < 10 secs
        # (Simplified for this snippet: just count unique ports per src->dst)
        # Ideally would need distinct port tracking.
        
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        
        sev, desc = calculate_severity(dst_port, "UDP")
        if sev != "LOW":
            severity = sev
            description = desc

    # Construct Packet Info
    pkt_data = {
        "id": len(traffic_log) + 1,
        "timestamp": timestamp,
        "src": src_ip,
        "sport": src_port,
        "dst": dst_ip,
        "dport": dst_port,
        "protocol": protocol,
        "len": length,
        "info": description if severity != "LOW" else f"{protocol} Packet",
        "severity": severity
    }

    # Add to Traffic Log
    traffic_log.appendleft(pkt_data) # Newest first

    # Logic for Alerts
    if severity in ["MEDIUM", "HIGH"]:
        alert = {
            "id": len(alerts) + 1,
            "timestamp": timestamp,
            "type": "Suspicious Activity",
            "source": f"{src_ip}:{src_port}",
            "target": f"{dst_ip}:{dst_port}",
            "severity": severity,
            "description": description
        }
        alerts.appendleft(alert)
        update_risk_score(severity)

def sniffer_thread():
    print("[-] Sniffer thread started...")
    sniff(prn=process_packet, store=False)

# --- Flask Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    # Calculate some summary stats
    high_alerts = sum(1 for a in alerts if a['severity'] == 'HIGH')
    med_alerts = sum(1 for a in alerts if a['severity'] == 'MEDIUM')
    
    return jsonify({
        "risk_score": risk_score,
        "alert_count": len(alerts),
        "traffic_count": len(traffic_log),
        "high_severity": high_alerts,
        "medium_severity": med_alerts,
        "uptime": (datetime.now() - start_time).seconds // 60
    })

@app.route('/api/alerts')
def get_alerts():
    return jsonify(list(alerts))

@app.route('/api/traffic')
def get_traffic():
    return jsonify(list(traffic_log))

if __name__ == '__main__':
    print_banner()
    
    # Start Sniffer in Background
    t = threading.Thread(target=sniffer_thread, daemon=True)
    t.start()
    
    print("[+] NetWatch v1.0 Starting Web Server on port 5000...")
    app.run(debug=True, use_reloader=False, port=5000)
