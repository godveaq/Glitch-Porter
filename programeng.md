# GLİTCH - Advanced Network Analysis and Security Scanning Tool

## Definition
GLİTCH is a comprehensive Python-based security tool developed for network security testing and network analysis. It includes many functions such as port scanning, vulnerability detection, proxy detection, and network discovery.

## Features

### 1. Port Scanning
- TCP Connect scanning
- SYN scanning (for stealth scanning)
- UDP scanning
- Scanning within specified port ranges
- Scanning on specific ports (e.g., 22,80,443)

### 2. Proxy Detection
- Detects proxy services running on open ports
- HTTP proxy detection
- Validates and reports proxy services

### 3. Network Discovery
- Determines the network range that the target IP belongs to
- Discovers other IP addresses active on the network
- Estimates the network gateway
- Shows DNS information

### 4. Vulnerability Scanning
- Detects security vulnerabilities for services running on open ports
- Scans vulnerabilities in common services like SSH, FTP, Web services
- Finds common vulnerabilities such as Anonymous FTP access

### 5. Web Scanning
- Detects security vulnerabilities on websites
- Finds missing security headers
- Scans sensitive directories and files

### 6. Packet Analysis
- Analyzes network traffic from PCAP files
- Detects suspicious activities
- Shows network protocols and IP statistics

### 7. Wireless Network Scanning
- Scans WiFi networks
- Shows SSID, BSSID, channel and encryption information

### 8. Network Discovery and Analysis
- Automatically determines the network range that the target IP belongs to
- Discovers other IP addresses active on the network
- Estimates the network gateway
- Shows DNS information

### 9. Proxy Detection
- Automatically detects proxy services during port scanning
- Performs HTTP proxy scanning
- Validates and adds proxy services to reports

## Usage

### Basic Usage
```bash
python glitch.py <target>
```

### Port Scanning
```bash
# Scanning within a specific port range
python glitch.py 192.168.1.1 -p 1-1000

# Scanning specific ports
python glitch.py 192.168.1.1 -p 22,80,443

# SYN scanning
python glitch.py 192.168.1.1 -p 1-1000 -t syn

# UDP scanning
python glitch.py 192.168.1.1 -p 53,137 -t udp
```

### Advanced Scanning
```bash
# Run all scanning types
python glitch.py --advanced 192.168.1.1

# Network scanning
python glitch.py --network-scan 192.168.1.0/24

# Web scanning
python glitch.py --web-scan example.com

# Wireless network scanning
python glitch.py --wireless-scan
```

## Example Usage and Results

### Example 1: Basic Port Scanning
```bash
python glitch.py 192.168.1.1 -p 22,80,443
```

**Output:**
```
GLITCH TARAMA RAPORU
===========================================================

Target: 192.168.1.1
Scan Time: 2025-12-28T12:54:42.326329
Hostname: ADSL
OS Guess: Linux/Unix

Statistics:
  Ports Scanned: 3
  Open Ports: 1
  Duration: 7.74 seconds
  Vulnerabilities Found: 4

NETWORK ANALYSIS:
  Network Range: 192.168.1.0/24
  Network Gateway: 192.168.1.1
  Discovered Hosts: 7
    - 192.168.1.1
    - 192.168.1.110
    - 192.168.1.102
    - 192.168.1.108
    - 192.168.1.109
    - 192.168.1.103
    - 192.168.1.107

OPEN PORTS:
Port    Protocol        Service         Banner              Proxy
---------------------------------------------------------
80      tcp             http            HTTP/1.1 400 Bad    HTTP Proxy: 192.168.1.1:80
Request
Cont...
```

### Example 2: Proxy Detection
Proxy services running on open ports are automatically detected and displayed in the "Proxy" column of the report.

### Example 3: Network Discovery
When a target IP address is provided, the program determines the network range that IP belongs to and scans other IP addresses active on the network.

## Reporting

### Text File Report
The program automatically saves scan results to a text file. The file naming format is:
```
glitch_scan_<target>_<date_time>.txt
```

### Report Contents
- Target information
- Network analysis results
- Open ports and service information
- Banner information
- Proxy information
- Detected vulnerabilities
- Network discovery results

## Command Line Arguments

| Argument | Description |
|----------|-------------|
| `target` | Target IP, hostname or network |
| `-p, --ports` | Port range to scan (default: 1-1000) |
| `-t, --scan-type` | Scan type (tcp, syn, udp, all) |
| `--threads` | Number of threads (default: 200) |
| `--timeout` | Timeout value (default: 1) |
| `--ping` | Perform ping scan |
| `--sniff` | Packet sniffing mode |
| `-i, --interface` | Network interface |
| `-c, --count` | Number of packets to sniff |
| `--vuln-scan` | Perform vulnerability scan |
| `-o, --output` | Output file |
| `--json` | Output in JSON format |
| `--csv` | Output in CSV format |
| `--advanced` | Advanced scanning |
| `--network-scan` | Network scanning |
| `--web-scan` | Web scanning |
| `--wireless-scan` | Wireless scanning |
| `--packet-analysis` | Packet analysis |
| `--pcap-file` | PCAP file analysis |

## Requirements

- Python 3.6 or higher
- Following Python libraries:
  - scapy
  - paramiko
  - dnspython
  - requests
  - netifaces

## Installation

```bash
pip install scapy paramiko dnspython requests netifaces
```

## License
This project is open source and can be used for educational purposes.