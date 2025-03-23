import time
import nmap
import socket
import sqlite3
import subprocess
from flask import Flask, jsonify, render_template, request
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

GENERAL_PORTS = "20,21,22,23,25,80,139,443,445,554,587,8000,8080,8888"


def create_db():
    """Creates a SQLite database for storing network device details."""
    create_blacklist_table()
    conn = sqlite3.connect("network_devices.db")
    c = conn.cursor()
    c.execute(
        """CREATE TABLE IF NOT EXISTS devices
                 (ip TEXT, mac TEXT, hostname TEXT, first_seen TEXT, last_seen TEXT,
                 PRIMARY KEY (mac))"""
    )
    conn.commit()
    conn.close()


def add_device_to_db(ip, mac, hostname):
    """Adds a new device or updates its last seen time in the database."""
    conn = sqlite3.connect("network_devices.db")
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        """INSERT INTO devices (ip, mac, hostname, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(mac) DO UPDATE SET last_seen=?""",
        (ip, mac, hostname, now, now, now),
    )
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
    """Scans a given IP for open ports using nmap."""
    print("TEST")
    scanner = nmap.PortScanner()
    open_ports = []
    try:
        scanner.scan(ip, ports)
        for proto in scanner[ip].all_protocols():
            for port in scanner[ip][proto].keys():
                if scanner[ip][proto][port]["state"] == "open":
                    service = scanner[ip][proto][port].get("name", "Unknown")
                    service_name = STREAMING_PORTS.get(port, service)
                    open_ports.append({"port": port, "service": service_name})
        return open_ports
    except Exception as e:
        print(f"Error scanning ports on {ip}: {e}")
        return []

def scan_for_streaming_ports(ip):
    """Check if any streaming-related ports are open and return their service names."""
    open_ports = scan_ports(ip, ','.join(map(str, STREAMING_PORTS.keys())))
    return open_ports


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

def get_hostname(ip):
    """Attempt to resolve the hostname of an IP address using nmap."""
    try:
        output = subprocess.check_output(['nmap', '-sL', '-R', ip], text=True)
        for line in output.splitlines():
            if "Nmap scan report" in line and "(" in line:
                return line.split("(")[1].strip(")")
        return "Unknown"
    except Exception as e:
        print(f"Error retrieving hostname with nmap for {ip}: {e}")
        return "Unknown"

def is_blacklisted(mac):
    """Check if a MAC address is blacklisted."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute("SELECT * FROM blacklist WHERE mac=?", (mac,))
    result = c.fetchone()
    conn.close()
    return result is not None

def scan_connected_devices(ip_range):
    """Scans the network for connected devices and updates the database."""
    scanner = nmap.PortScanner()
    devices = []
    try:
        scanner.scan(hosts=ip_range, arguments="-Pn -T5 -F")
        for host in scanner.all_hosts():
            if scanner[host].state() == "up":
                mac = scanner[host]["addresses"].get("mac", get_mac_from_arp(host))
                hostname = get_hostname(host)
                if is_blacklisted(mac):
                    print(f"Device {mac} is blacklisted. Skipping...")
                    continue
                device = {
                    "ip": host,
                    "mac": mac,
                    "hostname": hostname,
                }
                add_device_to_db(host, mac, hostname)
                devices.append(device)
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
        return []


def get_local_ip():
    """Retrieves the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error retrieving local IP address: {e}")
        return None


def get_network_range(local_ip):
    """Returns the IP range for scanning based on the local IP."""
    return f"{local_ip}/24"

def get_bssid():
    """Get the BSSID of the Wi-Fi network the main device is connected to."""
    try:
        output = subprocess.check_output(['iwconfig'], text=True)
        for line in output.splitlines():
            if 'Access Point' in line:
                return line.split('Access Point: ')[1].strip()
        return "Unknown"
    except Exception as e:
        print(f"Error retrieving BSSID: {e}")
        return "Unknown"
    
def create_blacklist_table():
    """Create blacklist table if it doesn't exist."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist
                 (mac TEXT PRIMARY KEY, reason TEXT, added_on TEXT)''')
    conn.commit()
    conn.close()


@app.route("/")
def index():
    """Renders the frontend UI."""
    return render_template("index copy.html")

@app.route('/home')
def home():
    """Render the home page."""
    return render_template('home.html')

@app.route('/aboutus')
def aboutus():
    """Render the about us page."""
    return render_template('aboutus.html')

@app.route('/login')
def login():
    """Render the login page."""
    return render_template('login.html')


@app.route("/hosts", methods=["GET"])
def hosts():
    """Scans the network and returns details about connected devices."""
    local_ip = get_local_ip()
    if not local_ip:
        return jsonify({"error": "Could not retrieve local IP address"}), 500
    ip_range = get_network_range(local_ip)
    devices = scan_connected_devices(ip_range)
    return jsonify({"current_ip": local_ip, "network_range": ip_range, "devices": devices}), 200

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

@app.route('/scan_port', methods=['GET'])
def handle_open_ports():
    ip = request.args.get('ip')
    open_ports = scan_ports(ip, GENERAL_PORTS)
    return {"ip": ip, "open_ports": open_ports}

@app.route('/blacklist/add/<mac>', methods=['GET'])
def add_to_blacklist(mac):
    """Add a device to the blacklist."""
    # reason = request.json.get("reason", "No reason provided")
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("INSERT OR IGNORE INTO blacklist (mac, added_on) VALUES (?, ?)", 
              (mac, now))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Device {mac} blacklisted successfully", "success":True}), 200

@app.route('/blacklist/remove/<mac>', methods=['GET'])
def remove_from_blacklist(mac):
    """Remove a device from the blacklist."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute("DELETE FROM blacklist WHERE mac=?", (mac,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Device {mac} removed from blacklist", "success": True}), 200


if __name__ == "__main__":
    create_db()
    app.run(host="127.0.0.1", port=5000, use_reloader=False)
