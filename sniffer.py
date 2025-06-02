from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time
import json
from datetime import datetime
import os
from threading import Thread, Lock
import logging
import requests
import ipaddress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='ids.log'
)

class NetworkMonitor:
    def __init__(self):
        self.port_scan_threshold = 10  # Number of different ports from same IP within timeframe
        self.login_attempt_threshold = 5  # Number of connection attempts to same port
        self.ssh_attempt_threshold = 5  # Number of SSH connection attempts
        self.ping_flood_threshold = 100  # Number of ICMP packets within timeframe
        self.timeframe = 60  # Time window in seconds
        
        # Tracking dictionaries
        self.ip_port_count = defaultdict(lambda: defaultdict(list))
        self.connection_attempts = defaultdict(lambda: defaultdict(int))
        self.ssh_attempts = defaultdict(lambda: defaultdict(int))
        self.ping_flood_count = defaultdict(lambda: defaultdict(int))
        self.alerts = []
        self.packet_stats = defaultdict(int)
        
        # Thread safety
        self.lock = Lock()
        
        # Create data directory if it doesn't exist
        os.makedirs('data', exist_ok=True)
        
        # Initialize whitelist
        self.whitelist = self.initialize_whitelist()
        
    def initialize_whitelist(self):
        """Initialize the IP whitelist with common cloud providers and trusted IPs"""
        whitelist = set()
        
        # Load whitelist from file if exists
        whitelist_file = 'data/whitelist.json'
        if os.path.exists(whitelist_file):
            try:
                with open(whitelist_file, 'r') as f:
                    whitelist = set(json.load(f))
            except Exception as e:
                logging.error(f"Error loading whitelist: {str(e)}")
        
        # Default trusted networks (example ranges)
        default_ranges = [
            '142.250.0.0/15',  # Google
            '104.196.0.0/14',  # Google Cloud
            '35.190.0.0/16',   # Google Cloud
            '52.0.0.0/12',     # Amazon AWS
            '13.32.0.0/15',    # Amazon CloudFront
            '18.130.0.0/16',   # Amazon AWS
            '18.156.0.0/16',   # Amazon AWS
            '18.160.0.0/16',   # Amazon AWS
            '18.164.0.0/16',   # Amazon AWS
            '18.168.0.0/16',   # Amazon AWS
            '18.172.0.0/16',   # Amazon AWS
            '18.176.0.0/16',   # Amazon AWS
        ]
        
        # Add default ranges to whitelist
        for ip_range in default_ranges:
            try:
                network = ipaddress.ip_network(ip_range)
                whitelist.add(str(network))
            except ValueError as e:
                logging.error(f"Invalid IP range in whitelist: {str(e)}")
        
        return whitelist
    
    def is_ip_whitelisted(self, ip):
        """Check if an IP is in the whitelist"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self.whitelist:
                if ip_obj in ipaddress.ip_network(network):
                    return True
        except ValueError:
            return False
        return False
    
    def add_to_whitelist(self, ip_or_network):
        """Add an IP or network to the whitelist"""
        try:
            # Validate the IP or network
            if '/' in ip_or_network:
                network = ipaddress.ip_network(ip_or_network)
                self.whitelist.add(str(network))
            else:
                ip = ipaddress.ip_address(ip_or_network)
                self.whitelist.add(str(ip))
            
            # Save updated whitelist
            with open('data/whitelist.json', 'w') as f:
                json.dump(list(self.whitelist), f)
            
            logging.info(f"Added {ip_or_network} to whitelist")
            return True
        except ValueError as e:
            logging.error(f"Invalid IP or network format: {str(e)}")
            return False
    
    def save_stats(self):
        """Save current statistics and alerts to files"""
        while True:
            with self.lock:
                # Save packet statistics
                with open('data/packet_stats.json', 'w') as f:
                    json.dump(dict(self.packet_stats), f)
                
                # Save alerts
                with open('data/alerts.json', 'w') as f:
                    json.dump(self.alerts[-100:], f)  # Keep last 100 alerts
            
            time.sleep(5)  # Update every 5 seconds
    
    def check_port_scan(self, src_ip, dst_port, timestamp):
        """Detect potential port scanning"""
        if self.is_ip_whitelisted(src_ip):
            return False
            
        self.ip_port_count[src_ip][timestamp].append(dst_port)
        
        # Check recent timeframe
        recent_ports = set()
        current_time = timestamp
        for t in list(self.ip_port_count[src_ip].keys()):
            if current_time - t > self.timeframe:
                del self.ip_port_count[src_ip][t]
            else:
                recent_ports.update(self.ip_port_count[src_ip][t])
        
        if len(recent_ports) > self.port_scan_threshold:
            alert = {
                'timestamp': datetime.fromtimestamp(timestamp).isoformat(),
                'type': 'Port Scan',
                'details': f'Possible port scan from {src_ip}: {len(recent_ports)} ports in {self.timeframe}s',
                'severity': 'High'
            }
            self.alerts.append(alert)
            logging.warning(f"Port scan detected: {alert['details']}")
            return True
        return False
    
    def check_ssh_brute_force(self, src_ip, dst_ip, dst_port):
        """Detect SSH brute force attempts"""
        if self.is_ip_whitelisted(src_ip):
            return False
            
        if dst_port == 22:  # SSH port
            key = f"{src_ip}->{dst_ip}:22"
            current_time = time.time()
            
            # Initialize or update attempt count
            if 'first_attempt' not in self.ssh_attempts[key]:
                self.ssh_attempts[key]['first_attempt'] = current_time
            self.ssh_attempts[key]['count'] += 1
            
            # Check if threshold exceeded within timeframe
            if (current_time - self.ssh_attempts[key]['first_attempt'] <= self.timeframe and 
                self.ssh_attempts[key]['count'] >= self.ssh_attempt_threshold):
                alert = {
                    'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                    'type': 'SSH Brute Force',
                    'details': f'Possible SSH brute force attack from {src_ip} to {dst_ip}',
                    'severity': 'High'
                }
                self.alerts.append(alert)
                logging.warning(f"SSH brute force detected: {alert['details']}")
                
                # Reset counter
                self.ssh_attempts[key]['count'] = 0
                self.ssh_attempts[key]['first_attempt'] = current_time
                return True
        return False
    
    def check_ping_flood(self, src_ip, timestamp):
        """Detect ICMP flood attacks"""
        if self.is_ip_whitelisted(src_ip):
            return False
            
        current_time = timestamp
        
        # Initialize or update ping count
        if 'first_ping' not in self.ping_flood_count[src_ip]:
            self.ping_flood_count[src_ip]['first_ping'] = current_time
        self.ping_flood_count[src_ip]['count'] += 1
        
        # Check if threshold exceeded within timeframe
        if (current_time - self.ping_flood_count[src_ip]['first_ping'] <= self.timeframe and 
            self.ping_flood_count[src_ip]['count'] >= self.ping_flood_threshold):
            alert = {
                'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                'type': 'Ping Flood',
                'details': f'Possible ICMP flood attack from {src_ip}: {self.ping_flood_count[src_ip]["count"]} pings in {self.timeframe}s',
                'severity': 'Medium'
            }
            self.alerts.append(alert)
            logging.warning(f"Ping flood detected: {alert['details']}")
            
            # Reset counter
            self.ping_flood_count[src_ip]['count'] = 0
            self.ping_flood_count[src_ip]['first_ping'] = current_time
            return True
        
        # Clean up old entries
        if current_time - self.ping_flood_count[src_ip]['first_ping'] > self.timeframe:
            self.ping_flood_count[src_ip]['count'] = 1
            self.ping_flood_count[src_ip]['first_ping'] = current_time
        
        return False
    
    def check_repeated_login(self, src_ip, dst_ip, dst_port):
        """Detect repeated login attempts"""
        if self.is_ip_whitelisted(src_ip):
            return False
            
        key = f"{src_ip}->{dst_ip}:{dst_port}"
        self.connection_attempts[key]['count'] += 1
        current_time = time.time()
        
        if 'first_attempt' not in self.connection_attempts[key]:
            self.connection_attempts[key]['first_attempt'] = current_time
        
        # Check if we've exceeded the threshold within the timeframe
        if (current_time - self.connection_attempts[key]['first_attempt'] <= self.timeframe and 
            self.connection_attempts[key]['count'] >= self.login_attempt_threshold):
            alert = {
                'timestamp': datetime.fromtimestamp(current_time).isoformat(),
                'type': 'Repeated Login',
                'details': f'Possible brute force from {src_ip} to {dst_ip}:{dst_port}',
                'severity': 'Medium'
            }
            self.alerts.append(alert)
            logging.warning(f"Repeated login attempts detected: {alert['details']}")
            self.connection_attempts[key]['count'] = 0
            self.connection_attempts[key]['first_attempt'] = current_time
            return True
        return False
    
    def packet_callback(self, packet):
        """Process each captured packet"""
        with self.lock:
            if IP in packet:
                timestamp = time.time()
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Update packet statistics
                self.packet_stats['total_packets'] += 1
                
                if TCP in packet:
                    dst_port = packet[TCP].dport
                    self.packet_stats['tcp_packets'] += 1
                    
                    # Check for port scanning
                    self.check_port_scan(src_ip, dst_port, timestamp)
                    
                    # Check for SSH brute force
                    self.check_ssh_brute_force(src_ip, dst_ip, dst_port)
                    
                    # Check for repeated login attempts on common ports
                    if dst_port in [21, 22, 23, 25, 110, 143, 443, 3389]:
                        self.check_repeated_login(src_ip, dst_ip, dst_port)
                
                elif UDP in packet:
                    self.packet_stats['udp_packets'] += 1
                
                elif ICMP in packet:
                    self.packet_stats['icmp_packets'] = self.packet_stats.get('icmp_packets', 0) + 1
                    # Check for ping flood
                    self.check_ping_flood(src_ip, timestamp)
                
                else:
                    self.packet_stats['other_packets'] += 1

    def start_monitoring(self, interface=None):
        """Start the network monitoring"""
        # Start the statistics saving thread
        stats_thread = Thread(target=self.save_stats, daemon=True)
        stats_thread.start()
        
        # Start packet sniffing
        logging.info(f"Starting packet capture{'on interface ' + interface if interface else ''}")
        sniff(iface=interface, prn=self.packet_callback, store=0)

if __name__ == "__main__":
    monitor = NetworkMonitor()
    try:
        monitor.start_monitoring(interface="en0")  # Explicitly specify en0 interface
    except KeyboardInterrupt:
        logging.info("Stopping network monitoring")
    except Exception as e:
        logging.error(f"Error in network monitoring: {str(e)}") 