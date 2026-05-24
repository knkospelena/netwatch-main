// ── State ────────────────────────────────────────────────────────────────────
let allAlerts = [];
let dpCurrentIP = '';

// ── SOC Response Playbooks (per attack_type) ─────────────────────────────────
const PLAYBOOKS = {
  "Port Scan": {
    immediate: [
      "Capture & save current packet capture for forensic evidence",
      "Identify all ports probed — check if any are open and exposed",
      "Block source IP at firewall immediately: <code>iptables -I INPUT -s {SRC} -j DROP</code>",
      "Alert your SOC team / incident response channel",
      "Check if scan tool signature matches Nmap, Masscan, or Zmap"
    ],
    short: [
      "Run netstat to verify which detected ports are actually listening: <code>ss -tlnp</code>",
      "Cross-reference open ports with your asset inventory",
      "Check auth logs for any successful login attempts from same IP: <code>grep {SRC} /var/log/auth.log</code>",
      "Search OSINT databases (Shodan, AbuseIPDB) for source IP reputation",
      "Verify firewall rules — ensure non-essential ports are blocked externally"
    ],
    long: [
      "Enable port-knocking or single-packet authorisation for SSH/admin services",
      "Deploy an IDS/IPS (Snort/Suricata) with port scan detection rules",
      "Implement rate-limiting at perimeter: max 10 connections/s per IP",
      "Segment network — critical systems should not be directly reachable",
      "Schedule quarterly external vulnerability scans to find exposed services proactively"
    ],
    tools: ["nmap -sV {DST}", "ss -tlnp", "iptables -I INPUT -s {SRC} -j DROP", "whois {SRC}"]
  },
  "Brute Force": {
    immediate: [
      "Block source IP immediately at host firewall",
      "Check if any login succeeded — review auth logs NOW: <code>grep 'Accepted' /var/log/auth.log</code>",
      "If login confirmed, kill active session: <code>pkill -u {USER}</code>",
      "Reset credentials for the targeted account",
      "Enable account lockout if not already active"
    ],
    short: [
      "Install fail2ban to auto-block brute force attempts: <code>apt install fail2ban</code>",
      "Enforce MFA on all remote access (SSH, RDP, VPN)",
      "Review all accounts for weak passwords — force password reset",
      "Check for other IPs in logs targeting same account (distributed brute force)",
      "Audit successful logins for last 7 days: <code>last -n 50</code>"
    ],
    long: [
      "Migrate SSH to key-based authentication only — disable password auth in sshd_config",
      "Move SSH/RDP behind VPN — no direct internet exposure",
      "Deploy CrowdSec or similar collaborative threat intelligence for IP reputation",
      "Implement SIEM alerting for >3 failed logins in 60 seconds",
      "Regularly audit user accounts and disable unused accounts"
    ],
    tools: ["grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn", "fail2ban-client status", "last -n 50", "who -a"]
  },
  "ICMP Flood": {
    immediate: [
      "Rate-limit ICMP at firewall: <code>iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT</code>",
      "Drop all other ICMP from source: <code>iptables -I INPUT -s {SRC} -p icmp -j DROP</code>",
      "Check if it is a reflection/amplification attack (spoofed source IPs)",
      "Verify if network bandwidth is saturated: <code>iftop -i eth0</code>",
      "Alert upstream ISP if bandwidth is saturated (request null-route of attacker IP)"
    ],
    short: [
      "Enable egress filtering to prevent your network being used as DDoS amplifier",
      "Check if multiple source IPs are involved (distributed flood)",
      "Analyse ICMP payload size — >1000 bytes per packet is abnormal",
      "Review network flow data (NetFlow/sFlow) for traffic patterns",
      "Engage DDoS mitigation service (Cloudflare, AWS Shield) if attack persists"
    ],
    long: [
      "Configure network devices to rate-limit ICMP globally (max 1 Mbps)",
      "Deploy traffic scrubbing / DDoS mitigation at ISP level",
      "Implement BCP38 ingress filtering to block spoofed source IPs",
      "Create monitoring alert for ICMP traffic exceeding baseline by >500%",
      "Document and test DDoS response runbook annually"
    ],
    tools: ["iftop -i eth0", "tcpdump -i eth0 icmp -n", "ping -f {SRC} (flood test in lab)", "iptables -L -n -v"]
  },
  "DNS Tunnelling": {
    immediate: [
      "Capture DNS traffic and inspect query names — look for long random subdomains",
      "Block DNS queries from suspicious host to external resolvers",
      "Force all DNS through your internal resolver only: block UDP/TCP 53 outbound except to approved DNS",
      "Isolate the source host from network pending investigation",
      "Preserve all DNS logs for forensic analysis"
    ],
    short: [
      "Analyse DNS query payload sizes — tunnelling queries are typically >60 bytes",
      "Look for high entropy domain names (e.g. a7fd3k2.evil.com) using dnscat2/iodine signatures",
      "Check the host for malware: run <code>ClamAV</code> or <code>chkrootkit</code>",
      "Review all DNS queries from host for last 24h in DNS server logs",
      "Search for known DNS tunnelling tools (iodine, dnscat2, dns2tcp) on the endpoint"
    ],
    long: [
      "Deploy DNS filtering (Pi-hole, Cisco Umbrella, NextDNS) with threat intelligence feeds",
      "Enable DNSSEC and DNS logging on all resolvers",
      "Alert on DNS query rate >10/s from a single host",
      "Implement DLP to detect exfiltration patterns in DNS",
      "Regularly audit egress traffic rules to prevent covert channels"
    ],
    tools: ["tcpdump -i eth0 port 53 -w dns.pcap", "tshark -r dns.pcap -Y 'dns' -T fields -e dns.qry.name", "dnstop eth0", "strings /proc/{PID}/exe | grep dns"]
  },
  "FTP Control": {
    immediate: [
      "Block port 21 at perimeter firewall immediately",
      "Check FTP server logs for successful logins: <code>grep 'USER\\|PASS\\|logged in' /var/log/vsftpd.log</code>",
      "Identify who is connecting and what files were accessed or uploaded",
      "Disable FTP service if not actively required: <code>systemctl stop vsftpd && systemctl disable vsftpd</code>"
    ],
    short: [
      "Replace FTP with SFTP (SSH File Transfer Protocol) or FTPS",
      "Review all files in FTP root for unauthorised uploads (webshells, malware)",
      "Audit FTP user accounts — remove all guest/anonymous access",
      "Check for any scheduled transfers or scripts using FTP credentials"
    ],
    long: [
      "Remove FTP software entirely if not required",
      "Implement SFTP with key-based authentication and chroot jails",
      "Use MFT (Managed File Transfer) solution with full audit logging",
      "Scan FTP directories for malicious file uploads weekly"
    ],
    tools: ["grep 'logged in' /var/log/vsftpd.log", "netstat -tlnp | grep 21", "clamscan -r /var/ftp/"]
  },
  "Telnet": {
    immediate: [
      "Block port 23 at firewall immediately — Telnet is unencrypted and critical risk",
      "Kill any active Telnet sessions: <code>pkill telnet</code>",
      "Check what device is running Telnet (could be IoT, router, legacy server)",
      "Assume all credentials transmitted over Telnet are COMPROMISED — reset them"
    ],
    short: [
      "Disable Telnet service completely: <code>systemctl disable telnet</code>",
      "If it is a network device (router/switch), enable SSH and disable Telnet in device config",
      "Audit all network devices for Telnet exposure using nmap: <code>nmap -p 23 {SUBNET}</code>",
      "Change all passwords that may have been transmitted in cleartext"
    ],
    long: [
      "Replace Telnet with SSH everywhere — enforce organisation-wide policy",
      "Run quarterly scans to detect any re-enabled Telnet services",
      "Implement network access control (NAC) to prevent legacy protocols",
      "Document all legacy systems requiring Telnet and create migration plan"
    ],
    tools: ["nmap -p 23 192.168.0.0/24", "systemctl status telnet", "tcpdump -i eth0 port 23 -A -n"]
  },
  "SMB": {
    immediate: [
      "Block ports 445 and 139 at perimeter firewall — NEVER expose SMB to internet",
      "Check for EternalBlue vulnerability: run <code>nmap --script smb-vuln-ms17-010 {DST}</code>",
      "Identify all SMB shares and who is connected: <code>smbstatus</code>",
      "If ransomware suspected — isolate host from network immediately"
    ],
    short: [
      "Apply MS17-010 patch if not already patched",
      "Disable SMBv1: <code>Set-SmbServerConfiguration -EnableSMB1Protocol $false</code>",
      "Audit SMB shares for excessive permissions — principle of least privilege",
      "Check for unusual file encryption activity (ransomware indicator): monitor .encrypted/.locked extensions",
      "Review Windows Event ID 4625 (failed login) and 4624 (successful login) via SMB"
    ],
    long: [
      "Disable SMBv1 and SMBv2 where possible — enforce SMBv3 with encryption",
      "Implement SMB signing to prevent NTLM relay attacks",
      "Deploy honeypot SMB share to detect lateral movement",
      "Segment network so workstations cannot directly SMB to each other",
      "Enable Windows Defender Credential Guard to protect NTLM hashes"
    ],
    tools: ["nmap --script smb-vuln-ms17-010 {DST}", "smbstatus", "net share", "Get-SmbSession (PowerShell)"]
  },
  "RDP": {
    immediate: [
      "Block port 3389 externally at firewall — RDP should NEVER be internet-facing",
      "Check active RDP sessions: <code>qwinsta /server:{DST}</code> or <code>who</code> on Linux",
      "Review Windows Security Event Log for Event ID 4624 (RDP logins) and 4625 (failed)",
      "If unauthorised session detected — disconnect: <code>logoff {SESSION_ID}</code>",
      "Reset any accounts that may have been compromised"
    ],
    short: [
      "Enable Network Level Authentication (NLA) — prevents pre-auth exploitation",
      "Move RDP behind VPN — users must VPN before RDP access",
      "Restrict RDP access by IP with firewall rules — whitelist only known admin IPs",
      "Enable RDP account lockout policy (5 attempts → 30 min lockout)",
      "Patch for BlueKeep (CVE-2019-0708) and DejaBlue if not already done"
    ],
    long: [
      "Deploy RDP gateway with certificate authentication",
      "Implement Privileged Access Workstation (PAW) policy for RDP admin access",
      "Enable RDP logging and forward to SIEM",
      "Use jump server / bastion host architecture instead of direct RDP",
      "Consider replacing RDP with a Zero Trust remote access solution (Cloudflare Access, Tailscale)"
    ],
    tools: ["qwinsta /server:{DST}", "netstat -an | grep 3389", "nmap --script rdp-vuln-ms12-020 {DST}", "Get-WinEvent -LogName Security | Where {$_.Id -eq 4624}"]
  },
  "Metasploit Shell": {
    immediate: [
      "CRITICAL — Isolate affected host from network IMMEDIATELY",
      "Do NOT power off — preserve volatile memory for forensics: <code>avml /tmp/memory.lime</code>",
      "Identify the process listening on 4444: <code>ss -tlnp | grep 4444</code>",
      "Take disk image before touching anything: <code>dd if=/dev/sda of=/mnt/evidence.img</code>",
      "Alert incident response team — this is a confirmed compromise"
    ],
    short: [
      "Analyse memory dump for Meterpreter/shellcode signatures",
      "Check crontabs, startup scripts, and systemd services for persistence: <code>crontab -l; ls /etc/cron*</code>",
      "Review all user accounts — look for new accounts created by attacker",
      "Check network connections from host: <code>ss -anp</code>",
      "Hash all running executables and compare against known-good baseline"
    ],
    long: [
      "Full forensic investigation and root cause analysis",
      "Rebuild affected system from clean image — do not trust a compromised system",
      "Conduct post-incident review and update detection rules",
      "Deploy EDR (Endpoint Detection and Response) on all hosts",
      "Implement network micro-segmentation to limit blast radius"
    ],
    tools: ["ss -tlnp | grep 4444", "ps aux | grep -E '4444|meterpreter'", "lsof -i :4444", "avml /tmp/memory.lime", "rkhunter --check"]
  },
  "IRC/Botnet C2": {
    immediate: [
      "Block port 6667 and all IRC ports (6660-6669, 7000) at perimeter",
      "Identify and isolate the host making IRC connections",
      "This host is likely part of a botnet — treat as COMPROMISED",
      "Preserve network logs and packet captures for law enforcement if needed",
      "Alert your ISP — they may have abuse team intelligence on botnet C2 server"
    ],
    short: [
      "Scan host for IRC-based botnet malware (IRCbot, mirai variants)",
      "Check all running processes for suspicious network connections",
      "Review DNS queries from host — botnet may use DGA (Domain Generation Algorithm)",
      "Check for rootkits: <code>rkhunter --check && chkrootkit</code>",
      "Lookup C2 server IP/domain in threat intelligence feeds (VirusTotal, OTX)"
    ],
    long: [
      "Rebuild affected host from clean image",
      "Block all IRC protocol at network level — no legitimate business use case",
      "Deploy DNS filtering to block known C2 domains",
      "Implement egress traffic monitoring and alerting for unusual outbound connections",
      "File abuse report with C2 server hosting provider"
    ],
    tools: ["rkhunter --check", "chkrootkit", "ss -anp | grep 6667", "tcpdump -i eth0 port 6667 -A"]
  },
  "Suspicious Activity": {
    immediate: [
      "Review the full alert details and source/destination IPs",
      "Correlate with other alerts from same source IP",
      "Check if the destination service should be accessible from source IP",
      "Capture traffic for manual analysis: <code>tcpdump -i eth0 host {SRC} -w capture.pcap</code>"
    ],
    short: [
      "Search logs for other activity from source IP",
      "Verify the legitimacy of the connection with system owner",
      "Check firewall rules — should this connection be allowed?",
      "Review user account activity if applicable"
    ],
    long: [
      "Update firewall rules to block if connection is confirmed unauthorised",
      "Add source IP to threat intelligence watchlist",
      "Create specific detection rule for this activity pattern",
      "Document findings in security incident log"
    ],
    tools: ["tcpdump -i eth0 host {SRC} -w capture.pcap", "grep {SRC} /var/log/syslog", "whois {SRC}"]
  }
};

function getPlaybook(attackType) {
  return PLAYBOOKS[attackType] || PLAYBOOKS["Suspicious Activity"];
}

// ── Open Detail Panel ─────────────────────────────────────────────────────────
function openDetail(alertId) {
  const a = allAlerts.find(x => x.id === alertId);
  if (!a) return;
  const srcIP = a.source.split(':')[0];
  dpCurrentIP = srcIP;

  document.getElementById('dp-title').textContent = a.attack_type || a.description;
  document.getElementById('dp-sub').textContent   = `Alert #${a.id} · ${a.timestamp} · ${a.severity}`;
  document.getElementById('dp-block-btn').innerHTML = `<i data-lucide="shield-off"></i> Block ${srcIP}`;

  const pb = getPlaybook(a.attack_type);

  const fmtTools = (tools, src, dst) => tools.map(t =>
    `<div class="cmd-box">${t.replace('{SRC}', src).replace('{DST}', dst.split(':')[0])}</div>`
  ).join('');

  const fmtSteps = (steps) => steps.map(s => `<li>${s}</li>`).join('');

  document.getElementById('dp-body').innerHTML = `
    <div class="dp-section">
      <div class="dp-section-title"><i data-lucide="info"></i> Alert Summary</div>
      <div class="dp-grid">
        <div class="dp-kv"><label>Severity</label><span class="badge ${a.severity}">${a.severity}</span></div>
        <div class="dp-kv"><label>Attack Type</label><span>${a.attack_type || '—'}</span></div>
        <div class="dp-kv"><label>Source</label><span>${a.source}</span></div>
        <div class="dp-kv"><label>Target</label><span>${a.target}</span></div>
        <div class="dp-kv"><label>Time</label><span>${a.timestamp}</span></div>
        <div class="dp-kv"><label>MITRE ATT&CK</label><span class="badge mitre">${a.mitre || 'N/A'}</span></div>
      </div>
      <div class="dp-desc">${a.detail || a.description}</div>
    </div>

    <div class="dp-section">
      <div class="dp-section-title"><i data-lucide="book-open"></i> SOC Response Playbook</div>

      <div class="phase-card immediate">
        <div class="phase-title"><i data-lucide="zap"></i> Phase 1 — Immediate (0–15 min)</div>
        <ul class="step-list">${fmtSteps(pb.immediate)}</ul>
      </div>

      <div class="phase-card short">
        <div class="phase-title"><i data-lucide="clock"></i> Phase 2 — Short-term (1–4 hours)</div>
        <ul class="step-list">${fmtSteps(pb.short)}</ul>
      </div>

      <div class="phase-card long">
        <div class="phase-title"><i data-lucide="shield-check"></i> Phase 3 — Long-term Hardening</div>
        <ul class="step-list">${fmtSteps(pb.long)}</ul>
      </div>
    </div>

    <div class="dp-section">
      <div class="dp-section-title"><i data-lucide="terminal"></i> Forensic Commands</div>
      ${fmtTools(pb.tools, srcIP, a.target)}
    </div>
  `;

  document.getElementById('detail-overlay').classList.add('open');
  document.getElementById('detail-panel').classList.add('open');
  if (window.lucide) lucide.createIcons();
}

function closeDetail() {
  document.getElementById('detail-overlay').classList.remove('open');
  document.getElementById('detail-panel').classList.remove('open');
}

function dpBlock() {
  if (dpCurrentIP) blockIP(dpCurrentIP);
}

// ── Render Alert Cards ────────────────────────────────────────────────────────
function renderAlerts() {
  const sevF = document.getElementById('sev-filter').value;
  const ipF  = document.getElementById('ip-filter').value.toLowerCase();
  const list = document.getElementById('alert-list');

  const filtered = allAlerts.filter(a => {
    if (sevF && a.severity !== sevF) return false;
    if (ipF && !a.source.toLowerCase().includes(ipF) && !a.target.toLowerCase().includes(ipF)) return false;
    return true;
  });

  if (!filtered.length) {
    list.innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)">No alerts match filter.</div>';
    return;
  }

  const sevIcon = { HIGH:'alert-triangle', MEDIUM:'alert-circle', CRITICAL:'skull', LOW:'info' };

  list.innerHTML = filtered.slice(0, 60).map(a => `
    <div class="alert-card ${a.severity}" onclick="openDetail(${a.id})">
      <div class="alert-top">
        <span class="badge ${a.severity}">
          <i data-lucide="${sevIcon[a.severity] || 'alert-circle'}" style="width:10px;height:10px;vertical-align:middle;margin-right:2px;"></i>
          ${a.severity}
        </span>
        <span class="badge type">${a.attack_type || 'Alert'}</span>
        ${a.mitre ? `<span class="badge mitre">MITRE ${a.mitre}</span>` : ''}
        <span class="alert-title">${a.description}</span>
        <span class="alert-meta" style="margin-left:auto">${a.timestamp}</span>
      </div>
      <div class="alert-route">
        <span class="ip-tag">${a.source}</span>
        <span class="arrow"> &rarr; </span>
        <span class="ip-tag">${a.target}</span>
      </div>
      <div class="click-hint">
        <i data-lucide="mouse-pointer-click"></i> Click to view full details &amp; response playbook
      </div>
    </div>
  `).join('');
  if (window.lucide) lucide.createIcons();
}

// ── Render Traffic Table ──────────────────────────────────────────────────────
function renderTraffic(data) {
  const tbody = document.querySelector('#traffic-table tbody');
  if (!data.length) return;
  tbody.innerHTML = data.map(p => {
    const rc = p.severity === 'HIGH' ? 'row-high' : p.severity === 'MEDIUM' ? 'row-medium' : '';
    return `<tr class="${rc}">
      <td>${p.timestamp}</td>
      <td>${p.protocol}</td>
      <td style="font-family:monospace">${p.src}:${p.sport}</td>
      <td style="color:var(--muted)">&rarr;</td>
      <td style="font-family:monospace">${p.dst}:${p.dport}</td>
      <td>${p.len}</td>
      <td>${p.info}</td>
      <td><span class="badge ${p.severity}">${p.severity}</span></td>
    </tr>`;
  }).join('');
}

// ── Render Top Talkers ────────────────────────────────────────────────────────
function renderTalkers(data) {
  const el = document.getElementById('talkers-list');
  if (!data.length) { el.innerHTML = '<div style="color:var(--muted)">No data yet.</div>'; return; }
  const max = data[0].count;
  el.innerHTML = data.map(t => `
    <div class="talker-bar">
      <span class="talker-ip">${t.ip}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(t.count/max*100).toFixed(1)}%"></div></div>
      <span class="talker-count">${t.count}</span>
      <button class="icon-btn danger" style="background:#fff;color:var(--red);border-color:rgba(220,38,38,.3);padding:2px 8px;font-size:11px;" onclick="blockIP('${t.ip}')">
        <i data-lucide="ban"></i> Block
      </button>
    </div>
  `).join('');
  if (window.lucide) lucide.createIcons();
}

// ── Render Blocked IPs ────────────────────────────────────────────────────────
function renderBlocked(data) {
  const el = document.getElementById('blocked-list');
  if (!data.length) { el.innerHTML = '<div style="color:var(--muted);padding:20px">No blocked IPs.</div>'; return; }
  el.innerHTML = data.map(ip => `<span class="blocked-tag"><i data-lucide="ban" style="width:12px;height:12px;"></i> ${ip}</span>`).join('');
  if (window.lucide) lucide.createIcons();
}

// ── Block IP ──────────────────────────────────────────────────────────────────
function blockIP(ip) {
  if (!ip || !ip.trim()) return;
  fetch('/api/block', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ip: ip.trim()})
  }).then(() => { fetchBlocked(); closeDetail(); });
}

// ── Clear Alerts ──────────────────────────────────────────────────────────────
function clearAlerts() {
  if (!confirm('Clear all alerts and reset risk score?')) return;
  fetch('/api/clear_alerts', {method:'POST'}).then(() => { allAlerts = []; renderAlerts(); });
}

// ── Tab Switching ─────────────────────────────────────────────────────────────
function openTab(id, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(id).classList.add('active');
  if (btn) btn.classList.add('active');
}

// ── Uptime ────────────────────────────────────────────────────────────────────
function fmtUptime(sec) {
  if (sec < 60) return sec + 's';
  if (sec < 3600) return Math.floor(sec/60) + 'm ' + (sec%60) + 's';
  return Math.floor(sec/3600) + 'h ' + Math.floor((sec%3600)/60) + 'm';
}

// ── API Fetchers ──────────────────────────────────────────────────────────────
function fetchStats() {
  fetch('/api/stats').then(r => r.json()).then(d => {
    document.getElementById('risk-score').textContent    = d.risk_score;
    document.getElementById('alert-count').textContent   = d.alert_count;
    document.getElementById('traffic-count').textContent = d.traffic_count;
    document.getElementById('high-count').textContent    = d.high_severity;
    document.getElementById('crit-count').textContent    = d.critical || 0;
    document.getElementById('blocked-count').textContent = d.blocked_ips || 0;
    document.getElementById('uptime-display').textContent = 'Uptime: ' + fmtUptime(d.uptime_sec);
    document.getElementById('last-updated').textContent  = 'Updated ' + new Date().toLocaleTimeString();
    const rs = document.getElementById('risk-score');
    rs.style.color = d.risk_score > 100 ? 'var(--purple)' : d.risk_score > 50 ? 'var(--red)' : 'var(--orange)';
  }).catch(() => {});
}

function fetchAlerts() {
  fetch('/api/alerts?limit=100').then(r => r.json()).then(d => {
    allAlerts = d;
    renderAlerts();
  }).catch(() => {});
}

function fetchTraffic() {
  if (!document.getElementById('tab-traffic').classList.contains('active')) return;
  fetch('/api/traffic?limit=100').then(r => r.json()).then(renderTraffic).catch(() => {});
}

function fetchTalkers() {
  if (!document.getElementById('tab-talkers').classList.contains('active')) return;
  fetch('/api/top_talkers').then(r => r.json()).then(renderTalkers).catch(() => {});
}

function fetchBlocked() {
  fetch('/api/blocked').then(r => r.json()).then(renderBlocked).catch(() => {});
}

// ── Poll ──────────────────────────────────────────────────────────────────────
function tick() {
  fetchStats(); fetchAlerts(); fetchTraffic(); fetchTalkers(); fetchBlocked();
}

document.addEventListener('DOMContentLoaded', () => {
  if (window.lucide) lucide.createIcons();
  setInterval(tick, 2500);
  tick();
});
