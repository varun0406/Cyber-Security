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

def create_db():
    """Create SQLite database and devices table if not exists."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS devices
                 (ip TEXT, mac TEXT, hostname TEXT, first_seen TEXT, last_seen TEXT,
                 PRIMARY KEY (mac))''')
    conn.commit()
    conn.close()
    
    # Create blacklist table
    create_blacklist_table()
    
    # Create users table
    with app.app_context():
        db.create_all()

def create_blacklist_table():
    """Create blacklist table if it doesn't exist."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS blacklist
                 (mac TEXT PRIMARY KEY, reason TEXT, added_on TEXT)''')
    conn.commit()
    conn.close()

def is_blacklisted(mac):
    """Check if a MAC address is blacklisted."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute("SELECT * FROM blacklist WHERE mac=?", (mac,))
    result = c.fetchone()
    conn.close()
    return result is not None

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
            'last_seen': row[4],
            'is_blacklisted': is_blacklisted(row[1])
        })
    return devices

def scan_ports(ip, ports):
    """Scan a device for open ports and their associated services."""
    scanner = nmap.PortScanner()
    open_ports = []

    try:
        start_time = time.time()
        scanner.scan(ip, ports)
        
        for proto in scanner[ip].all_protocols():
            lport = scanner[ip][proto].keys()
            for port in lport:
                if scanner[ip][proto][port]['state'] == 'open':
                    service = scanner[ip][proto][port].get('name', 'Unknown')
                    service_name = STREAMING_PORTS.get(int(port), service)
                    open_ports.append({
                        'port': port,
                        'service': service_name
                    })
        
        end_time = time.time()
        print(f"Port scan completed in {end_time - start_time:.2f} seconds")
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
        output = subprocess.check_output(['arp', '-a', ip], text=True)
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if '-' in part or ':' in part:  # MAC addresses typically contain - or :
                        return part
        return "N/A"
    except Exception as e:
        print(f"Error retrieving MAC address for {ip}: {e}")
        return "N/A"

def get_hostname(ip):
    """Attempt to resolve the hostname of an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        try:
            # Fallback to nmap for hostname resolution
            output = subprocess.check_output(['nmap', '-sL', ip], text=True)
            for line in output.splitlines():
                if ip in line and "(" in line and ")" in line:
                    hostname = line.split("(")[0].strip()
                    if hostname and hostname != ip:
                        return hostname
        except Exception as e:
            print(f"Error retrieving hostname with nmap for {ip}: {e}")
        return "Unknown"

def scan_connected_devices(ip_range):
    """Scan the network for connected devices."""
    scanner = nmap.PortScanner()
    devices = []
    
    try:
        print(f"Scanning network range: {ip_range}")
        scanner.scan(hosts=ip_range, arguments='-sn')  # Ping scan
        
        for host in scanner.all_hosts():
            if scanner[host].state() == "up":
                mac = scanner[host]['addresses'].get('mac', None)
                if not mac:
                    mac = get_mac_from_arp(host)
                
                hostname = get_hostname(host)
                
                # Skip blacklisted devices if needed
                # if is_blacklisted(mac):
                #     print(f"Device {mac} is blacklisted. Skipping...")
                #     continue
                
                device = {
                    'ip': host,
                    'mac': mac,
                    'hostname': hostname,
                    'is_blacklisted': is_blacklisted(mac)
                }
                
                # Add device to history database
                add_device_to_db(host, mac, hostname)
                
                devices.append(device)
        
        return devices
    except Exception as e:
        print(f"Error scanning network: {e}")
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
    ip_parts = local_ip.split('.')
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

def get_bssid():
    """Get the BSSID of the Wi-Fi network the main device is connected to."""
    try:
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True)
            for line in output.splitlines():
                if 'BSSID' in line:
                    return line.split(':')[1].strip()
        else:  # Linux/macOS
            output = subprocess.check_output(['iwconfig'], text=True)
            for line in output.splitlines():
                if 'Access Point' in line:
                    return line.split('Access Point: ')[1].strip()
        return "Unknown"
    except Exception as e:
        print(f"Error retrieving BSSID: {e}")
        return "Unknown"

# Routes

@app.route('/')
def index():
    """Redirect to login page or home if already logged in."""
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')

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
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            next_page = request.form.get('next', url_for('home'))
            flash('Logged in successfully!', 'success')
            return redirect(next_page)
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

@app.route('/scan_port', methods=['GET'])
@login_required
def handle_open_ports():
    """Scan a specific IP for open ports."""
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400
    
    try:
        open_ports = scan_ports(ip, GENERAL_PORTS)
        return jsonify({"ip": ip, "open_ports": open_ports})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/hosts')
@login_required
def hosts():
    """Scan the network and render results."""
    try:
        local_ip = get_local_ip()
        if not local_ip:
            flash("Could not retrieve local IP address", "danger")
            return redirect(url_for('home'))
        
        ip_range = get_network_range(local_ip)
        devices = scan_connected_devices(ip_range)
        
        return render_template('devices_scan.html', 
                            devices=devices, 
                            current_ip=local_ip, 
                            network_range=ip_range)
    except Exception as e:
        flash(f"Error scanning network: {str(e)}", "danger")
        return redirect(url_for('home'))

@app.route('/api/hosts', methods=['GET'])
@login_required
def api_hosts():
    """API endpoint for network scanning."""
    local_ip = get_local_ip()
    if not local_ip:
        return jsonify({"error": "Could not retrieve local IP address"}), 500
    
    ip_range = get_network_range(local_ip)
    devices = scan_connected_devices(ip_range)
    
    return jsonify({
        "current_ip": local_ip,
        "network_range": ip_range,
        "devices": devices
    })

@app.route('/view_devices', methods=['GET'])
@login_required
def show_stored_devices():
    """Retrieve and display historical device tracking information."""
    devices = view_devices()
    return render_template('devices.html', devices=devices)

@app.route('/blacklist/add/<mac>', methods=['GET'])
@login_required
def add_to_blacklist(mac):
    """Add a device to the blacklist."""
    reason = request.args.get('reason', 'No reason provided')
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        c.execute("INSERT INTO blacklist (mac, reason, added_on) VALUES (?, ?, ?)", 
                (mac, reason, now))
        conn.commit()
        conn.close()
        flash(f'Device {mac} has been blacklisted', 'success')
        return jsonify({"message": f"Device {mac} blacklisted successfully", "success": True}), 200
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e), "success": False}), 500

@app.route('/blacklist/remove/<mac>', methods=['GET'])
@login_required
def remove_from_blacklist(mac):
    """Remove a device from the blacklist."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    
    try:
        c.execute("DELETE FROM blacklist WHERE mac=?", (mac,))
        conn.commit()
        conn.close()
        flash(f'Device {mac} has been removed from blacklist', 'success')
        return jsonify({"message": f"Device {mac} removed from blacklist", "success": True}), 200
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e), "success": False}), 500

@app.route('/view_blacklist', methods=['GET'])
@login_required
def view_blacklist():
    """View all blacklisted devices."""
    conn = sqlite3.connect('network_devices.db')
    c = conn.cursor()
    c.execute('SELECT * FROM blacklist')
    rows = c.fetchall()
    conn.close()
    
    blacklisted_devices = []
    for row in rows:
        blacklisted_devices.append({
            'mac': row[0],
            'reason': row[1] if row[1] else "No reason provided",
            'added_on': row[2]
        })
    
    return render_template('blacklist.html', devices=blacklisted_devices)

# Required modules
import os

if __name__ == "__main__":
    create_db()
    app.run(debug=True, host='0.0.0.0', port=5000)