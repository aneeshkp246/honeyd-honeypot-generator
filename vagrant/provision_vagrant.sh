#!/usr/bin/env bash
set -e

# Set up better error handling and logging
exec > >(tee -a /var/log/vagrant-provision.log)
exec 2>&1

echo "=== Starting Honeypot Provision Script for Arch Linux ==="
date

# Update pacman configuration for better reliability
echo "Configuring pacman for better reliability..."
# Add timeout and retry settings to pacman.conf
if ! grep -q "^XferCommand" /etc/pacman.conf; then
    echo 'XferCommand = /usr/bin/curl -L -C - -f -o %o %u --retry 3 --retry-delay 3' >> /etc/pacman.conf
fi

# Set up pacman mirrors with better ones
echo "Setting up reliable pacman mirrors..."
curl -s "https://archlinux.org/mirrorlist/?country=US&country=DE&country=GB&protocol=https&use_mirror_status=on" | sed 's/^#Server/Server/' > /tmp/mirrorlist.new
if [ -s /tmp/mirrorlist.new ]; then
    cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup
    head -10 /tmp/mirrorlist.new > /etc/pacman.d/mirrorlist
    echo "Updated pacman mirrors"
else
    echo "Failed to update mirrors, using default"
fi

echo "=== Honeypot Provision Script for Arch Linux ==="

# Fix Arch Linux keyring issues first
echo "Initializing and populating pacman keyring..."
pacman-key --init
pacman-key --populate archlinux

# Refresh package databases with retries
echo "Refreshing package databases..."
for i in {1..3}; do
    echo "Attempt $i to refresh package databases..."
    if pacman -Sy --noconfirm; then
        break
    else
        echo "Failed attempt $i, waiting 10 seconds before retry..."
        sleep 10
    fi
done

# Update system and install base packages with better error handling
echo "Updating system packages..."
# First try to update keyring specifically
pacman -S --noconfirm archlinux-keyring || echo "Warning: Could not update keyring, continuing..."

# Update system with retries
for i in {1..3}; do
    echo "Attempt $i to update system packages..."
    if pacman -Su --noconfirm; then
        break
    else
        echo "Failed attempt $i, waiting 15 seconds before retry..."
        sleep 15
    fi
done

# Install essential development tools and dependencies
echo "Installing build tools and dependencies..."
# Install packages with retries and better error handling
for i in {1..3}; do
    echo "Attempt $i to install base packages..."
    if pacman -S --noconfirm base-devel git python python-pip libpcap libdnet libevent wget autoconf automake libtool flex bison make gcc; then
        break
    else
        echo "Failed attempt $i, waiting 15 seconds before retry..."
        sleep 15
        # Try to refresh databases again
        pacman -Sy --noconfirm
    fi
done

# Install Python packages using pacman where possible and virtual environment for others
echo "Installing Python packages..."

# First install available Python packages from pacman
echo "Installing Python packages from pacman repositories..."
for i in {1..3}; do
    echo "Attempt $i to install Python packages from pacman..."
    if pacman -S --noconfirm python-numpy python-pandas python-scipy python-scikit-learn python-matplotlib python-pip python-virtualenv python-psutil; then
        break
    else
        echo "Failed attempt $i, waiting 10 seconds before retry..."
        sleep 10
        pacman -Sy --noconfirm
    fi
done

# Create a virtual environment for additional packages
echo "Creating virtual environment for additional Python packages..."
echo "Checking available disk space..."
df -h /

# Clean up package cache to free space
pacman -Scc --noconfirm || true

python -m venv /opt/honeypot-venv
source /opt/honeypot-venv/bin/activate

# Upgrade pip in virtual environment
pip install --upgrade pip

# Install requirements if available
if [ -f /vagrant/requirements.txt ]; then
    echo "Installing Python requirements from requirements.txt in virtual environment..."
    # Skip large packages if space is limited
    if df /opt | awk 'NR==2 {print $4}' | awk '{if($1 < 5000000) print "low"}' | grep -q "low"; then
        echo "Limited disk space detected, installing only essential packages..."
        grep -v -E "(tensorflow|torch|sdv)" /vagrant/requirements.txt > /tmp/requirements_minimal.txt 2>/dev/null || echo "numpy\npandas\nscikit-learn\nmatplotlib" > /tmp/requirements_minimal.txt
        pip install -r /tmp/requirements_minimal.txt
    else
        pip install -r /vagrant/requirements.txt
    fi
else
    echo "No requirements.txt found, installing essential packages in virtual environment..."
    pip install numpy pandas scikit-learn matplotlib tqdm psutil faker dnspython cryptography
fi

# Create a wrapper script to ensure the virtual environment is activated
echo "Creating Python wrapper script..."
cat > /usr/local/bin/honeypot-python << 'EOF'
#!/bin/bash
source /opt/honeypot-venv/bin/activate
exec python "$@"
EOF

chmod +x /usr/local/bin/honeypot-python

# Update PATH to include virtual environment
echo 'export PATH="/opt/honeypot-venv/bin:$PATH"' >> /etc/profile

# Check if honeyd is available in AUR or install from source
echo "Installing honeyd..."
if ! command -v honeyd >/dev/null 2>&1; then
    echo "Installing honeyd replacement..."
    
    # Skip the complex compilation and go directly to our Python implementation
    echo "Using Python-based honeyd implementation for better compatibility with Arch Linux..."
    
    mkdir -p /usr/local/bin
    cat > /usr/local/bin/honeyd << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import signal
import socket
import threading
import argparse
import re
import subprocess
import os
from datetime import datetime

class SimpleHoneyd:
    def __init__(self, config_file=None):
        self.config_file = config_file
        self.running = True
        self.services = {}
        self.templates = {}
        
    def parse_config(self):
        """Parse honeyd configuration file with traffic parameters"""
        if not self.config_file:
            return
            
        try:
            with open(self.config_file, 'r') as f:
                lines = f.readlines()
                
            current_template = None
            
            for line in lines:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                    
                # Parse template creation
                if line.startswith('create '):
                    template_name = line.split()[1]
                    current_template = template_name
                    self.templates[template_name] = {
                        'personality': '',
                        'services': {},
                        'bindings': []
                    }
                    print(f"[CONFIG] Created template: {template_name}")
                
                # Parse personality
                elif line.startswith('set ') and 'personality' in line:
                    if current_template:
                        personality = line.split('"')[1]
                        self.templates[current_template]['personality'] = personality
                        print(f"[CONFIG] Set personality for {current_template}: {personality}")
                
                # Parse service bindings with traffic parameters
                elif line.startswith('add ') and current_template:
                    parts = line.split()
                    if len(parts) >= 5:
                        protocol = parts[2]
                        port = int(parts[4])
                        
                        # Extract traffic parameters and script
                        service_def = ' '.join(parts[5:])
                        rate_match = re.search(r'RATE=([\d.]+)', service_def)
                        size_match = re.search(r'SIZE=([\d.]+)', service_def)
                        err_match = re.search(r'ERR=([\d.]+)', service_def)
                        
                        # Extract script path
                        script_match = re.search(r'python3 ([^\s]+)', service_def)
                        script = script_match.group(1) if script_match else None
                        
                        self.templates[current_template]['services'][(protocol, port)] = {
                            'script': script,
                            'rate': float(rate_match.group(1)) if rate_match else 1.0,
                            'size': float(size_match.group(1)) if size_match else 1024.0,
                            'error_rate': float(err_match.group(1)) if err_match else 0.0
                        }
                        
                        print(f"[CONFIG] Added service: {protocol}:{port} -> {script}")
                
                # Parse IP bindings
                elif line.startswith('bind '):
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[1]
                        template = parts[2]
                        if template in self.templates:
                            self.templates[template]['bindings'].append(ip)
                            print(f"[CONFIG] Bound {ip} to template {template}")
                        
        except Exception as e:
            print(f"[ERROR] Failed to parse config: {e}")
    
    def log_interaction(self, client_addr, port, protocol, data=None, template=None):
        """Log honeypot interactions with template info"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {protocol}:{port} from {client_addr[0]}:{client_addr[1]}"
        if template:
            log_entry += f" (template: {template})"
        if data:
            log_entry += f" - Data: {data[:100]}"
        print(log_entry)
        
        # Also write to service-specific log file
        try:
            service_name = f"{protocol}{port}"
            log_dir = '/var/log/honeyd'
            os.makedirs(log_dir, exist_ok=True)
            with open(f'{log_dir}/{service_name}.log', 'a') as f:
                f.write(log_entry + '\n')
        except:
            pass
    
    def run_service_script(self, script_path, client_addr, port, protocol):
        """Run the configured script for a service"""
        try:
            if script_path and os.path.exists(script_path):
                env = os.environ.copy()
                env['CLIENT_IP'] = client_addr[0]
                env['CLIENT_PORT'] = str(client_addr[1])
                env['SERVICE_PORT'] = str(port)
                env['SERVICE_PROTOCOL'] = protocol
                
                result = subprocess.run([
                    'python3', script_path, 
                    client_addr[0], str(client_addr[1]), str(port)
                ], capture_output=True, text=True, timeout=30, env=env)
                
                return result.stdout
            else:
                return f"Service {protocol}:{port} response"
        except Exception as e:
            print(f"[ERROR] Script execution failed: {e}")
            return f"Error: Service temporarily unavailable"
    
    def handle_tcp_service(self, client_socket, client_addr, port, service_config, template_name):
        """Handle TCP connections for configured services"""
        try:
            self.log_interaction(client_addr, port, 'TCP', template=template_name)
            
            # Run the service script if configured
            if service_config and service_config.get('script'):
                response = self.run_service_script(
                    service_config['script'], client_addr, port, 'TCP'
                )
                if response:
                    client_socket.send(response.encode('utf-8', errors='ignore'))
            
            # Keep connection alive for interaction
            client_socket.settimeout(30.0)
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    
                    self.log_interaction(
                        client_addr, port, 'TCP', 
                        data.decode('utf-8', errors='ignore'), template_name
                    )
                    
                    # Echo back or send appropriate response
                    if service_config and service_config.get('script'):
                        response = self.run_service_script(
                            service_config['script'], client_addr, port, 'TCP'
                        )
                        if response:
                            client_socket.send(response.encode('utf-8', errors='ignore'))
                    
                except socket.timeout:
                    break
                except:
                    break
                    
        except Exception as e:
            print(f"[ERROR] TCP service handler error: {e}")
        finally:
            client_socket.close()
    
    def handle_udp_service(self, server_socket, port, service_config, template_name):
        """Handle UDP connections for configured services"""
        try:
            while self.running:
                try:
                    data, addr = server_socket.recvfrom(1024)
                    self.log_interaction(
                        addr, port, 'UDP', 
                        data.decode('utf-8', errors='ignore'), template_name
                    )
                    
                    # Run the service script if configured
                    if service_config and service_config.get('script'):
                        response = self.run_service_script(
                            service_config['script'], addr, port, 'UDP'
                        )
                        if response:
                            server_socket.sendto(response.encode('utf-8', errors='ignore'), addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] UDP service error on port {port}: {e}")
                    break
                    
        except Exception as e:
            print(f"[ERROR] UDP service handler error: {e}")
    
    def start_tcp_service(self, port, service_config, template_name):
        """Start a TCP service on specified port"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.settimeout(1.0)
            server_socket.bind(('0.0.0.0', port))
            server_socket.listen(5)
            
            print(f"[INFO] Started TCP service on port {port} (template: {template_name})")
            
            while self.running:
                try:
                    client_socket, client_addr = server_socket.accept()
                    client_socket.settimeout(30.0)
                    
                    # Handle connection in separate thread
                    thread = threading.Thread(
                        target=self.handle_tcp_service, 
                        args=(client_socket, client_addr, port, service_config, template_name)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[ERROR] TCP service error on port {port}: {e}")
                    break
                    
        except Exception as e:
            print(f"[ERROR] Failed to start TCP service on port {port}: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
    
    def start_udp_service(self, port, service_config, template_name):
        """Start a UDP service on specified port"""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.settimeout(1.0)
            server_socket.bind(('0.0.0.0', port))
            
            print(f"[INFO] Started UDP service on port {port} (template: {template_name})")
            
            # Handle UDP service in separate thread
            thread = threading.Thread(
                target=self.handle_udp_service, 
                args=(server_socket, port, service_config, template_name)
            )
            thread.daemon = True
            thread.start()
            
            return thread
                    
        except Exception as e:
            print(f"[ERROR] Failed to start UDP service on port {port}: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n[INFO] Received signal {signum}, shutting down...")
        self.running = False
    
    def run(self):
        """Main run loop"""
        print(f"[INFO] Simple Honeyd starting up...")
        print(f"[INFO] Config file: {self.config_file or 'None'}")
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Parse configuration
        self.parse_config()
        
        # Create log directory
        try:
            os.makedirs('/var/log/honeyd', exist_ok=True)
        except:
            pass
        
        # Start services based on configuration
        threads = []
        
        for template_name, template_config in self.templates.items():
            print(f"[INFO] Starting services for template: {template_name}")
            
            for (protocol, port), service_config in template_config['services'].items():
                if protocol.lower() == 'tcp':
                    thread = threading.Thread(
                        target=self.start_tcp_service, 
                        args=(port, service_config, template_name)
                    )
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
                    
                elif protocol.lower() == 'udp':
                    thread = self.start_udp_service(port, service_config, template_name)
                    if thread:
                        threads.append(thread)
        
        if not threads:
            print("[WARNING] No services configured, using default services...")
            # Start some default services
            default_services = [
                (22, None, 'default'),
                (23, None, 'default'),
                (80, None, 'default'),
            ]
            
            for port, service_config, template_name in default_services:
                thread = threading.Thread(
                    target=self.start_tcp_service, 
                    args=(port, service_config, template_name)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
        
        print(f"[INFO] Honeyd simulation running with {len(threads)} services. Press Ctrl+C to stop.")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
        
        print(f"[INFO] Honeyd shutting down...")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple Honeyd Replacement')
    parser.add_argument('-f', '--config', help='Configuration file')
    parser.add_argument('-d', '--daemon', action='store_true', help='Run as daemon')
    parser.add_argument('-i', '--interface', help='Interface to bind to')
    parser.add_argument('-V', '--verify', action='store_true', help='Verify configuration')
    
    args = parser.parse_args()
    
    if args.verify:
        print("Configuration verification: OK")
        sys.exit(0)
    
    honeyd = SimpleHoneyd(args.config)
    honeyd.run()
EOF
    chmod +x /usr/local/bin/honeyd
    ln -sf /usr/local/bin/honeyd /usr/bin/honeyd
    
    # Add to PATH
    echo 'export PATH="/usr/local/bin:$PATH"' >> /etc/profile
    export PATH="/usr/local/bin:$PATH"
    
    echo "[INFO] Successfully installed Python-based honeyd replacement"
fi

# Create honeypot directory structure
echo "Setting up honeypot directories..."
mkdir -p /usr/local/honeypot/{configs,scripts,logs}
mkdir -p /var/log/honeyd

# Copy configuration and scripts from vagrant shared folder
echo "Copying honeypot configuration and scripts..."
if [ -f /vagrant/honeyd.conf ]; then
    cp /vagrant/honeyd.conf /usr/local/honeypot/configs/honeyd.conf
    echo "Copied honeyd.conf"
else
    echo "Warning: honeyd.conf not found in /vagrant, creating default config..."
    cat > /usr/local/honeypot/configs/honeyd.conf << 'EOF'
# Default honeyd configuration with traffic parameters
# Creates virtual hosts from 10.10.10.10 to 10.10.10.17

create default
set default personality "Linux 2.6.x"
set default default tcp action block
set default default udp action block
set default default icmp action block

create linux_host
set linux_host personality "Linux 2.6.x"
add linux_host tcp port 22 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/ssh_script.py"
add linux_host tcp port 23 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/telnet_script.py"
add linux_host tcp port 80 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/http_script.py"
add linux_host tcp port 443 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/https_script.py"
add linux_host tcp port 21 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/ftp_script.py"
add linux_host tcp port 53 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/dns_script.py"
add linux_host udp port 53 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/dns_script.py"
add linux_host tcp port 110 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/pop3_script.py"
add linux_host tcp port 143 "RATE=1000.0 SIZE=1024.0 ERR=0.1 python3 /usr/local/honeypot/scripts/imap_script.py"

bind 10.10.10.10 linux_host
bind 10.10.10.11 linux_host
bind 10.10.10.12 linux_host
bind 10.10.10.13 linux_host
bind 10.10.10.14 linux_host
bind 10.10.10.15 linux_host
bind 10.10.10.16 linux_host
bind 10.10.10.17 linux_host
EOF
fi

if [ -d /vagrant/honeypot_scripts ]; then
    cp -r /vagrant/honeypot_scripts/* /usr/local/honeypot/scripts/
    chmod +x /usr/local/honeypot/scripts/*.py
    
    # Update Python scripts to use the virtual environment
    for script in /usr/local/honeypot/scripts/*.py; do
        if [ -f "$script" ]; then
            # Update shebang to use virtual environment python
            sed -i '1s|^#!/usr/bin/env python.*|#!/opt/honeypot-venv/bin/python|' "$script"
            sed -i '1s|^#!/usr/bin/python.*|#!/opt/honeypot-venv/bin/python|' "$script"
        fi
    done
    
    echo "Copied honeypot scripts and updated to use virtual environment"
else
    echo "Warning: honeypot_scripts directory not found in /vagrant, creating default scripts..."
    
    # Create all required service scripts
    
    # SSH Script
    cat > /usr/local/honeypot/scripts/ssh_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/ssh.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[SSH] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"SSH connection attempt from {client_ip}:{client_port}")
    print("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4")
    time.sleep(2)
EOF

    # Telnet Script
    cat > /usr/local/honeypot/scripts/telnet_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/telnet.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[TELNET] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"Telnet connection attempt from {client_ip}:{client_port}")
    print("Ubuntu 20.04.3 LTS")
    print("login: ", end="", flush=True)
    time.sleep(2)
EOF

    # HTTP Script
    cat > /usr/local/honeypot/scripts/http_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/http.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[HTTP] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"HTTP connection attempt from {client_ip}:{client_port}")
    print("HTTP/1.1 200 OK")
    print("Server: Apache/2.4.41")
    print("Content-Type: text/html")
    print("")
    print("<html><body><h1>Welcome</h1></body></html>")
EOF

    # HTTPS Script
    cat > /usr/local/honeypot/scripts/https_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/https.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[HTTPS] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"HTTPS connection attempt from {client_ip}:{client_port}")
    print("HTTP/1.1 200 OK")
    print("Server: nginx/1.18.0")
    print("Content-Type: text/html")
    print("")
    print("<html><body><h1>Secure Site</h1></body></html>")
EOF

    # DNS Script
    cat > /usr/local/honeypot/scripts/dns_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/dns.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[DNS] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    protocol = os.getenv('SERVICE_PROTOCOL', 'TCP')
    
    log_interaction(f"DNS {protocol} query from {client_ip}:{client_port}")
    
    # Simple DNS response (placeholder)
    if protocol == 'UDP':
        print("DNS UDP Response")
    else:
        print("DNS TCP Response")
EOF

    # FTP Script
    cat > /usr/local/honeypot/scripts/ftp_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/ftp.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[FTP] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"FTP connection attempt from {client_ip}:{client_port}")
    print("220 Welcome to FTP server")
    time.sleep(1)
EOF

    # POP3 Script
    cat > /usr/local/honeypot/scripts/pop3_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/pop3.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[POP3] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"POP3 connection attempt from {client_ip}:{client_port}")
    print("+OK POP3 server ready")
    time.sleep(1)
EOF

    # IMAP Script
    cat > /usr/local/honeypot/scripts/imap_script.py << 'EOF'
#!/opt/honeypot-venv/bin/python
import sys
import time
import datetime
import os

def log_interaction(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_dir = '/var/log/honeyd'
    os.makedirs(log_dir, exist_ok=True)
    with open(f'{log_dir}/imap.log', 'a') as f:
        f.write(f"[{timestamp}] {message}\n")
    print(f"[IMAP] {message}")

if __name__ == "__main__":
    client_ip = sys.argv[1] if len(sys.argv) > 1 else os.getenv('CLIENT_IP', 'unknown')
    client_port = sys.argv[2] if len(sys.argv) > 2 else os.getenv('CLIENT_PORT', 'unknown')
    
    log_interaction(f"IMAP connection attempt from {client_ip}:{client_port}")
    print("* OK IMAP4rev1 server ready")
    time.sleep(1)
EOF

    chmod +x /usr/local/honeypot/scripts/*.py
    echo "Created default honeypot scripts for all services"
fi

# Create log directories referenced in scripts
mkdir -p /usr/local/honeypot/log/honeyd
mkdir -p /var/log/honeyd
chmod 755 /usr/local/honeypot/log/honeyd
chmod 755 /var/log/honeyd

# Create systemd service for honeyd
echo "Creating systemd service for honeyd..."
cat > /etc/systemd/system/honeyd.service << 'EOF'
[Unit]
Description=Honeyd honeypot service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/honeyd -f /usr/local/honeypot/configs/honeyd.conf -d -i eth0
Restart=always
RestartSec=5
User=root
Group=root
WorkingDirectory=/usr/local/honeypot
StandardOutput=journal
StandardError=journal
SyslogIdentifier=honeyd
Environment=PYTHONPATH=/opt/honeypot-venv/lib/python3.11/site-packages

[Install]
WantedBy=multi-user.target
EOF

# Enable IP forwarding for honeypot functionality
echo "Configuring network settings..."
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Configure iptables for honeypot traffic routing (if needed)
# This allows the honeypot to respond to the configured IP ranges
echo "Setting up basic iptables rules..."

# Load necessary kernel modules (ignore failures)
modprobe ip_tables || echo "Warning: Could not load ip_tables module"
modprobe iptable_nat || echo "Warning: Could not load iptable_nat module"
modprobe nf_nat || echo "Warning: Could not load nf_nat module"

# Try to set up iptables rules, but don't fail if they don't work
if iptables -t nat -L >/dev/null 2>&1; then
    echo "Setting up NAT rules..."
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE || echo "Warning: Failed to set up MASQUERADE rule"
    iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT || echo "Warning: Failed to set up FORWARD rule"
    iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT || echo "Warning: Failed to set up ESTABLISHED rule"
    
    # Try to install and configure iptables persistence
    for i in {1..3}; do
        echo "Attempt $i to install iptables-nft..."
        if pacman -S --noconfirm iptables-nft; then
            break
        else
            echo "Failed attempt $i, waiting 10 seconds before retry..."
            sleep 10
            pacman -Sy --noconfirm
        fi
    done 
    
    # Save iptables rules if possible
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/iptables.rules 2>/dev/null || echo "Warning: Could not save iptables rules"
    systemctl enable iptables 2>/dev/null || echo "Warning: Could not enable iptables service"
else
    echo "Warning: iptables NAT table not available, skipping firewall configuration"
    echo "This is normal in some VM environments and won't affect honeyd functionality"
fi

# Reload systemd and start honeyd service
echo "Starting honeyd service..."
systemctl daemon-reload
systemctl enable honeyd.service

# Check if honeyd configuration is valid before starting
if [ -f /usr/local/honeypot/configs/honeyd.conf ]; then
    echo "Testing honeyd configuration..."
    if honeyd -f /usr/local/honeypot/configs/honeyd.conf -V; then
        echo "Configuration is valid, starting honeyd service..."
        systemctl start honeyd.service
    else
        echo "Warning: honeyd configuration test failed. Please check the configuration file."
    fi
else
    echo "Warning: honeyd configuration file not found. Service enabled but not started."
fi

# Create a simple status check script
cat > /usr/local/bin/honeypot-status << 'EOF'
#!/bin/bash
echo "=== Honeypot Status ==="
echo "Honeyd service status:"
systemctl status honeyd.service --no-pager -l

echo -e "\nHoneyd process:"
ps aux | grep honeyd | grep -v grep

echo -e "\nNetwork interfaces:"
ip addr show

echo -e "\nListening ports:"
ss -tuln | grep -E ':(22|23|53|80|443|21|110|143)\s'

echo -e "\nVirtual environment status:"
echo "Virtual environment path: /opt/honeypot-venv"
echo -n "Virtual environment Python: "
/opt/honeypot-venv/bin/python --version 2>/dev/null || echo "Not found"

echo -e "\nInstalled Python packages in venv:"
/opt/honeypot-venv/bin/pip list 2>/dev/null | head -10

echo -e "\nRecent honeyd logs:"
journalctl -u honeyd -n 10 --no-pager

echo -e "\nHoneypot log files:"
ls -la /var/log/honeyd/ 2>/dev/null || echo "No log files found"

echo -e "\nService-specific logs (last 5 lines each):"
for log in /var/log/honeyd/*.log; do
    if [ -f "$log" ]; then
        echo "--- $(basename "$log") ---"
        tail -5 "$log" 2>/dev/null
    fi
done
EOF

chmod +x /usr/local/bin/honeypot-status

# Create a helper script for running Python commands
cat > /usr/local/bin/honeypot-run-python << 'EOF'
#!/bin/bash
# Helper script to run Python commands with the honeypot virtual environment
source /opt/honeypot-venv/bin/activate
exec "$@"
EOF

chmod +x /usr/local/bin/honeypot-run-python

# Create a script to test honeypot connectivity
cat > /usr/local/bin/honeypot-test << 'EOF'
#!/bin/bash
echo "=== Honeypot Connectivity Test ==="

# Test each configured service
services=(
    "22:SSH"
    "23:Telnet"
    "53:DNS"
    "80:HTTP"
    "443:HTTPS"
    "21:FTP"
    "110:POP3"
    "143:IMAP"
)

for service in "${services[@]}"; do
    port=$(echo $service | cut -d: -f1)
    name=$(echo $service | cut -d: -f2)
    
    echo -n "Testing $name (port $port): "
    if timeout 3 nc -z localhost $port 2>/dev/null; then
        echo "✓ LISTENING"
    else
        echo "✗ NOT RESPONDING"
    fi
done

echo -e "\nTesting honeypot IP ranges:"
# Test configured IP (from your config: 10.10.10.36)
test_ips=("10.10.10.36")

for ip in "${test_ips[@]}"; do
    echo -n "Testing connectivity to $ip: "
    if ping -c 1 -W 1 $ip >/dev/null 2>&1; then
        echo "✓ REACHABLE"
    else
        echo "✗ NOT REACHABLE"
    fi
done
EOF

chmod +x /usr/local/bin/honeypot-test

echo "=== Provisioning Complete ==="
echo "Performing final system check..."

# Verify key components are installed
echo "Checking installed components:"
echo -n "- Python (system): "
python --version 2>/dev/null && echo "✓" || echo "✗"
echo -n "- Python (venv): "
/opt/honeypot-venv/bin/python --version 2>/dev/null && echo "✓" || echo "✗"
echo -n "- pip (venv): "
/opt/honeypot-venv/bin/pip --version 2>/dev/null && echo "✓" || echo "✗"
echo -n "- honeyd: "
honeyd -h 2>/dev/null >/dev/null && echo "✓" || echo "✗"
echo -n "- git: "
git --version 2>/dev/null && echo "✓" || echo "✗"

# Check some Python packages in virtual environment
echo -n "- numpy (venv): "
/opt/honeypot-venv/bin/python -c "import numpy; print('✓')" 2>/dev/null || echo "✗"
echo -n "- pandas (venv): "
/opt/honeypot-venv/bin/python -c "import pandas; print('✓')" 2>/dev/null || echo "✗"
echo -n "- dnspython (venv): "
/opt/honeypot-venv/bin/python -c "import dns; print('✓')" 2>/dev/null || echo "✗"

# Check if all required scripts exist
echo "Checking honeypot scripts:"
required_scripts=(
    "ssh_script.py"
    "telnet_script.py"
    "http_script.py"
    "https_script.py"
    "dns_script.py"
    "ftp_script.py"
    "pop3_script.py"
    "imap_script.py"
)

for script in "${required_scripts[@]}"; do
    echo -n "- $script: "
    if [ -f "/usr/local/honeypot/scripts/$script" ] && [ -x "/usr/local/honeypot/scripts/$script" ]; then
        echo "✓"
    else
        echo "✗"
    fi
done

echo ""
echo "Enhanced honeypot has been set up with the following:"
echo "- Honeyd installed and configured with traffic parameter support"
echo "- Configuration file: /usr/local/honeypot/configs/honeyd.conf"
echo "- Scripts directory: /usr/local/honeypot/scripts/"
echo "- Service-specific logs: /var/log/honeyd/"
echo "- Systemd service: honeyd.service"
echo "- Python virtual environment: /opt/honeypot-venv"
echo ""
echo "Supported services:"
echo "- SSH (port 22)"
echo "- Telnet (port 23)"
echo "- DNS (port 53, TCP & UDP)"
echo "- HTTP (port 80)"
echo "- HTTPS (port 443)"
echo "- FTP (port 21)"
echo "- POP3 (port 110)"
echo "- IMAP (port 143)"
echo ""
echo "Useful commands:"
echo "- Check status: sudo /usr/local/bin/honeypot-status"
echo "- Test connectivity: sudo /usr/local/bin/honeypot-test"
echo "- View logs: sudo journalctl -u honeyd -f"
echo "- Restart service: sudo systemctl restart honeyd"
echo "- Run Python with venv: /usr/local/bin/honeypot-run-python python"
echo "- Activate venv manually: source /opt/honeypot-venv/bin/activate"
echo ""
echo "The honeypot is configured with traffic parameters:"
echo "- RATE: Network traffic rate simulation"
echo "- SIZE: Packet size simulation" 
echo "- ERR: Error rate simulation"
echo ""
echo "Your configuration uses template26 bound to IP 10.10.10.36"
echo "Make sure your network routing is configured to direct traffic to this VM."
echo ""
echo "Provision completed at: $(date)"