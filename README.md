# Network Intrusion Detection System (NIDS)

A simple network intrusion detection system built with Python that monitors network traffic, detects suspicious patterns, and displays alerts through a Streamlit dashboard.

> **AI Assistance Disclaimer**: This application was developed with the assistance of artificial intelligence (Claude 3.5 Sonnet). This includes composing this README file, refactoring function code, architecture setup and recommendation of imports to use. 

## Features

### Network Monitoring
- Real-time network packet sniffing using Scapy
- Support for TCP, UDP, and ICMP protocols
- Detailed packet statistics and traffic analysis

### Attack Detection
- Port scan detection
- SSH brute force attack detection
- Ping flood (ICMP flood) detection
- Repeated login attempt detection
- IP whitelisting for trusted sources (e.g., Amazon AWS, Google Cloud)

### Dashboard Features
- Live traffic visualization
- Protocol distribution analysis
- Attack type distribution charts
- Real-time alert monitoring
- Severity-based alert filtering (High, Medium, Low)
- Attack type categorization
- Responsive and compact layout

## Requirements

- Python 3.8+
- Administrator/root privileges (for packet sniffing)
- Required Python packages (install using requirements.txt)
- Windows: Npcap library installed (for packet capture)

## Installation

1. Clone this repository:
   ```bash
   git clone <repository-url>
   cd Network-IDS
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Linux/Mac:
   source venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

4. Windows Users Only:
   - Download and install Npcap from [npcap.com](https://npcap.com/#download)
   - Make sure to check "WinPcap Compatibility Mode" during installation

## Usage

The system consists of two main components that need to be run separately:

### 1. Packet Sniffer (requires admin/root privileges)

```bash
# On Windows: Run PowerShell/CMD as Administrator
python sniffer.py

# On Linux:
sudo python sniffer.py
```

The sniffer will:
- Monitor network traffic in real-time
- Detect suspicious activities
- Log alerts and statistics
- Save data for dashboard visualization

### 2. Dashboard

```bash
streamlit run dashboard.py
```

The dashboard will automatically open in your default browser at `http://localhost:8501` and shows:
- Real-time packet statistics
- Traffic distribution charts
- Attack type distribution
- Categorized alerts with severity levels

## Configuration

### Sniffer Settings
In `sniffer.py`, you can adjust detection thresholds:
```python
self.port_scan_threshold = 10     # Number of different ports from same IP within timeframe
self.login_attempt_threshold = 5   # Number of connection attempts to same port
self.ssh_attempt_threshold = 5     # Number of SSH connection attempts
self.ping_flood_threshold = 100    # Number of ICMP packets within timeframe
self.timeframe = 60               # Time window in seconds
```

### IP Whitelisting
The system comes with pre-configured whitelist ranges for common cloud providers. To add custom IPs/ranges:

1. Create/edit `data/whitelist.json`
2. Add IP addresses or CIDR ranges:
   ```json
   [
     "192.168.1.100",
     "10.0.0.0/24",
     "172.16.0.0/16"
   ]
   ```

## File Structure

- `sniffer.py`: Core packet capture and analysis module
- `dashboard.py`: Streamlit-based web dashboard
- `requirements.txt`: Python package dependencies
- `data/`: Directory for storing runtime data
  - `packet_stats.json`: Current packet statistics (created on first run)
  - `alerts.json`: Recent alerts (created on first run)
  - `whitelist.json`: Whitelisted IP addresses/ranges (can be created to whitelist certain IP's. Check ./sniffer.py for format)

## Alert Types

1. **Port Scan**
   - Severity: High
   - Triggered when multiple different ports are accessed from the same IP

2. **SSH Brute Force**
   - Severity: High
   - Triggered by repeated SSH connection attempts

3. **Ping Flood**
   - Severity: Medium
   - Triggered by excessive ICMP packets from a single source

4. **Repeated Login**
   - Severity: Medium
   - Triggered by multiple connection attempts to common service ports

## Security Note

This tool is for educational and monitoring purposes only. Always ensure you have proper authorization before monitoring network traffic. The system should be used responsibly and in compliance with applicable laws and regulations.

## Troubleshooting

1. **Packet Capture Issues**
   - Ensure you're running with administrator/root privileges
   - Windows: Verify Npcap is installed correctly
   - Check firewall settings

2. **Dashboard Not Updating**
   - Verify the sniffer is running and capturing packets
   - Check the `data` directory exists and is writable
   - Ensure no file permission issues

3. **High CPU Usage**
   - Adjust the dashboard update interval (default: 2 seconds)
   - Consider increasing detection thresholds for busy networks
