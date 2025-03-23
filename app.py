import time
import nmap
import socket
import sqlite3
import subprocess
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime

# Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_db():
    """Create SQLite database and devices table if not exists."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (ip TEXT, mac TEXT, hostname TEXT, first_seen TEXT, last_seen TEXT,
                 PRIMARY KEY (mac))''')
    conn.commit()
    conn.close()
    with app.app_context():
        db.create_all()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('login'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('login'))

        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))

    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    """Render the home page."""
    return render_template('home.html')

@app.route('/aboutus')
@login_required
def aboutus():
    """Render the about us page."""
    return render_template('aboutus.html')

@app.route('/hosts', methods=['GET'])
@login_required
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
@login_required
def show_stored_devices():
    """Retrieve and display historical device tracking information."""
    devices = view_devices()
    if devices:
        return render_template('devices.html', devices=devices)
    else:
        return jsonify({
            "message": "No devices found in the history"
        }), 404

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
    """Scan a device for open ports and their associated services."""
    scanner = nmap.PortScanner()
    open_ports = []

    try:
        start_time = time.time()  # Start time for port scanning
        scanner.scan(ip, ports)
        
        for proto in scanner[ip].all_protocols():
            lport = scanner[ip][proto].keys()
            for port in lport:
                if scanner[ip][proto][port]['state'] == 'open':
                    service = scanner[ip][proto][port].get('name', 'Unknown')
                    service_name = STREAMING_PORTS.get(port, service)  # If port is in STREAMING_PORTS, use it
                    open_ports.append({
                        'port': port,
                        'service': service_name
                    })
        
        end_time = time.time()  # End time for port scanning
        print(f"Port scan completed in {end_time - start_time:.2f} seconds")  # Log duration
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

def scan_connected_devices(ip_range):
    """Scan the network for connected devices."""
    scanner = nmap.PortScanner()
    devices = []
    
    try:
        start_time = time.time()  # Start time for device scanning
        print(f"Scanning network range: {ip_range}")  # Debugging statement
        scanner.scan(hosts=ip_range, arguments='-Pn -T4')  # Enhanced scanning
        print(f"Discovered hosts: {scanner.all_hosts()}")  # Debugging statement

        for host in scanner.all_hosts():
            if scanner[host].state() == "up":
                print(f"Host {host} is up")  # Debugging statement
                mac = scanner[host]['addresses'].get('mac', get_mac_from_arp(host))
                hostname = get_hostname(host)  # Resolve hostname

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
                    'bssid': get_bssid(),  # Get the BSSID of the current network
                }

                # Add device to history database
                add_device_to_db(host, mac, hostname)

                devices.append(device)
        end_time = time.time()  # End time for device scanning
        print(f"Network scan completed in {end_time - start_time:.2f} seconds")  # Log duration
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

@app.route('/')
def index():
    """Render the index page."""
    return render_template('index.html')

@app.route('/deauth/<bssid>/<client_mac>', methods=['POST'])
def deauth(bssid, client_mac):
    """Deauthenticate a device based on BSSID and Client MAC address."""
    result = deauthenticate_device(bssid, client_mac)
    return jsonify(result)

if __name__ == "__main__":
    create_db()
    app.run(debug=True, host='0.0.0.0', port=5000)