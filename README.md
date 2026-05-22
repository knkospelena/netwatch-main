# NetWatch

**NetWatch** is a Python-based **network traffic monitoring and intrusion detection tool**.  
It captures network packets, analyzes traffic, detects suspicious activity, and provides a **real-time web dashboard**.

Inspired by tools like **nmap, Wireshark, and Metasploit**, NetWatch is designed for security enthusiasts, pentesters, and network administrators.

---

## Features

- Real-time packet sniffing (TCP, UDP, ICMP, ARP)
- Detection of **suspicious ports and protocols**:
  - FTP, Telnet, SMB, RDP, SSH
- Alerts for:
  - Port scanning
  - SSH brute force attempts
  - ICMP flood attacks
  - Unusual DNS activity
- **Risk scoring system** based on activity severity
- Real-time **web dashboard** using Flask
- Logs traffic and alerts in structured format

---

## Requirements

- Python 3.10+  
- Linux (recommended)  
- Python packages:
  ```bash
  pip install scapy flask pyfiglet
  ```

> Note: **Root privileges** are required for packet sniffing.

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/knkospelena/netwatch.git
   cd NetWatch
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run NetWatch**:
   ```bash
   sudo python3 netwatch.py
   ```

---

## Usage

- Open a terminal and run:
  ```bash
  sudo python3 main.py
  ```
- Access the web dashboard at:
  ```
  http://127.0.0.1:5000
  ```
- Monitor live traffic, alerts, and risk score in real-time.

---

## Project Structure

```
NetWatch/
├── netwatch.py        # Core sniffer and Flask server
├── logger.py          # Logging utility
├── templates/         # Flask HTML templates
│   └── index.html
├── static/            # CSS/JS for dashboard
│   └── style.css
├── README.md          # Project documentation
└── requirements.txt   # Python dependencies
```

---

## Contributing

Contributions are welcome!  

1. Fork the repository  
2. Create a feature branch (`git checkout -b feature-name`)  
3. Commit your changes (`git commit -m "Add feature"`)  
4. Push to your branch (`git push origin feature-name`)  
5. Open a Pull Request  

---

## License

License © knkospelena

---

## Disclaimer

**NetWatch is intended for educational purposes only.**  
Do **not** use it to monitor networks you do not have permission to access.
