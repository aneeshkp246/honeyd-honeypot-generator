#!/usr/bin/env bash
set -e
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo ./provision_honeypot_vm.sh"
  exit 2
fi
apt update && apt install -y build-essential git python3 python3-pip libpcap-dev libdnet-dev libevent-dev wget autoconf automake libtool flex bison
# Try apt honeyd or build from source
if ! command -v honeyd >/dev/null 2>&1; then
  echo "Attempting to install honeyd from apt..."
  apt install -y honeyd || true
fi
pip3 install --upgrade pip
if [ -f /home/ubuntu/honeypot-pipeline/requirements.txt ]; then
  pip3 install -r /home/ubuntu/honeypot-pipeline/requirements.txt || true
fi
mkdir -p /usr/local/honeypot/{configs,scripts,logs}
cp /home/ubuntu/honeypot-pipeline/honeyd.conf /usr/local/honeypot/configs/honeyd.conf || true
cp -r /home/ubuntu/honeypot-pipeline/honeypot_scripts/* /usr/local/honeypot/scripts/ || true
chmod +x /usr/local/honeypot/scripts/*.py || true
cat >/etc/systemd/system/honeyd.service <<'EOF'
[Unit]
Description=Honeyd honeypot service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/honeyd -f /usr/local/honeypot/configs/honeyd.conf -d -i eth0
Restart=always
User=root
WorkingDirectory=/usr/local/honeypot
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=honeyd

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable honeyd.service
systemctl start honeyd.service
echo "Provisioning complete. Check logs: sudo journalctl -u honeyd -f"
