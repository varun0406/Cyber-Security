import nmap
import socket
import sqlite3
import subprocess
from flask import Flask, jsonify, render_template
from datetime import datetime

# Flask app
app = Flask(__name__)

# Video and audio streaming-related ports
STREAMING_PORTS = {
    554: "RTSP (Real-Time Streaming Protocol)",
    1935: "RTMP (Real-Time Messaging Protocol)",
    8080: "HTTP Alternative (Video Streaming)",
    8000: "Alternative HTTP (Streaming)",
    443: "HTTPS (Encrypted Video Streaming)",
    80: "HTTP (Standard Streaming)",
    3478: "STUN (Session Traversal Utilities for NAT)",
    5349: "TURN (Traversal Using Relays around NAT)",
    5000: "Apple AirPlay (Audio/Video Streaming)",
    5060: "SIP (Session Initiation Protocol)",
    5061: "SIP (Encrypted with TLS)",
    16384: "RTP (Real-time Transport Protocol, start range)",
    32767: "RTP (Real-time Transport Protocol, end range)",
    1900: "UPnP (Universal Plug and Play)",
    2869: "DLNA (Digital Living Network Alliance)",
}

# General ports to scan for basic device functionality
GENERAL_PORTS = "20,21,22,23,25,80,139,443,445,554,587,8000,8080,8888"

# Database setup
def create_db():
    """Create SQLite database and devices table if not exists."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (ip TEXT, mac TEXT, hostname TEXT, first_seen TEXT, last_seen TEXT,
                 PRIMARY KEY (mac))''')
    conn.commit()
    conn.close()

def add_device_to_db(ip, mac, hostname):
    """Insert or update device information in the SQLite database."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''INSERT INTO devices (ip, mac, hostname, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(mac) DO UPDATE SET last_seen=?''',
              (ip, mac, hostname, now, now, now))
    conn.commit()
    conn.close()

def view_devices():
    """Retrieve all device records from the SQLite database."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('SELECT * FROM devices')
    rows = c.fetchall()
    conn.close()
    
    devices = []
    for row in rows:
        devices.append({
            'ip': row[0],
            'mac': row[1],
            'hostname': row[2],
            'first_seen': row[3],
            'last_seen': row[4]
        })
    return devices

def scan_ports(ip, ports):
    """Scan a device for open ports."""
    scanner = nmap.PortScanner()
    open_ports = []
    
    try:
        scanner.scan(ip, ports)
        for proto in scanner[ip].all_protocols():
            lport = scanner[ip][proto].keys()
            for port in lport:
                if scanner[ip][proto][port]['state'] == 'open':
                    open_ports.append(port)
        return open_ports
    except Exception as e:
        print(f"Error scanning ports on {ip}: {e}")
        return []

def scan_for_streaming_ports(ip):
    """Check if any streaming-related ports are open."""
    open_ports = scan_ports(ip, ','.join(map(str, STREAMING_PORTS.keys())))
    return [
        {
            'port': port,
            'service': STREAMING_PORTS.get(port, 'Unknown')
        } for port in open_ports
    ]

def get_mac_from_arp(ip):
    """Get the MAC address of a device using the ARP table."""
    try:
        output = subprocess.check_output(['arp', '-n', ip], text=True)
        for line in output.splitlines():
            if ip in line:
                return line.split()[2]  # Assumes MAC is the third column
    except Exception as e:
        print(f"Error retrieving MAC address for {ip}: {e}")  # Debugging statement
    return "N/A"

def scan_connected_devices(ip_range):
    """Scan the network for connected devices."""
    scanner = nmap.PortScanner()
    devices = []
    
    try:
        print(f"Scanning network range: {ip_range}")  # Debugging statement
        scanner.scan(hosts=ip_range, arguments='-Pn -T4')  # Enhanced scanning
        print(f"Discovered hosts: {scanner.all_hosts()}")  # Debugging statement

        for host in scanner.all_hosts():
            if scanner[host].state() == "up":
                print(f"Host {host} is up")  # Debugging statement
                mac = scanner[host]['addresses'].get('mac', get_mac_from_arp(host))
                hostname = scanner[host].hostname() or 'Unknown'

                # Scan general ports
                general_ports_open = scan_ports(host, GENERAL_PORTS)

                # Check for streaming ports
                streaming_ports = scan_for_streaming_ports(host)

                device = {
                    'ip': host,
                    'mac': mac,
                    'hostname': hostname,
                    'open_ports': general_ports_open if general_ports_open else None,
                    'streaming_ports': streaming_ports if streaming_ports else None,
                }

                # Add device to history database
                add_device_to_db(host, mac, hostname)

                devices.append(device)
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")  # Debugging statement
        return []

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))  
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error retrieving local IP address: {e}")
        return None

def get_network_range(local_ip):
    """Get the network range for the local IP address (assuming a /24 subnet)."""
    return f"{local_ip}/24"

@app.route('/hosts', methods=['GET'])
def hosts():
    """Retrieve the list of connected devices, current IP, network range, and streaming ports."""
    local_ip = get_local_ip()
    if not local_ip:
        return jsonify({"error": "Could not retrieve local IP address"}), 500

    ip_range = get_network_range(local_ip)

    devices = scan_connected_devices(ip_range)

    if devices:
        return jsonify({
            "current_ip": local_ip,
            "network_range": ip_range,
            "devices": devices
        }), 200
    else:
        return jsonify({
            "current_ip": local_ip,
            "network_range": ip_range,
            "message": "No devices found on the network"
        }), 404

@app.route('/view_devices', methods=['GET'])
def show_stored_devices():
    """Retrieve and display historical device tracking information."""
    devices = view_devices()
    if devices:
        return render_template('devices.html', devices=devices)
    else:
        return jsonify({
            "message": "No devices found in the history"
        }), 404

@app.route('/deauth/<bssid>/<client_mac>', methods=['POST'])
def deauth(bssid, client_mac):
    """Deauthenticate a device based on BSSID and Client MAC address."""
    # Placeholder for actual deauthentication logic
    return jsonify({"message": "Deauthentication request sent."})

if __name__ == "__main__":
    create_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
