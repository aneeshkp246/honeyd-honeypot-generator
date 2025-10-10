# Packet Capture Configuration

This document describes the packet capture functionality added to the honeypot provisioning script.

## Overview

The provisioning script has been enhanced to install Wireshark (tshark) and automatically capture all network packets for forensic analysis and honeypot monitoring.

## Directory Structure

The following directories are created during provisioning:

```
/capture/
├── pcaps/           # All packet captures stored here
└── honeyd_logs/     # Honeyd logs synced here every 5 minutes
```

## Installed Components

- **wireshark-cli** (tshark): Command-line packet analyzer
- **tcpdump**: Additional packet capture tool
- **Automatic capture rotation**: Prevents disk space issues

## Systemd Services

### 1. tshark-capture.service
- **Purpose**: Continuously captures all network packets
- **Capture location**: `/capture/pcaps/`
- **File naming**: `capture_YYYYMMDD_HHMMSS.pcap`
- **Rotation**: Creates new file every hour (3600 seconds)
- **File limit**: Keeps last 50 files automatically

**Commands**:
```bash
sudo systemctl status tshark-capture    # Check status
sudo systemctl start tshark-capture     # Start capture
sudo systemctl stop tshark-capture      # Stop capture
sudo systemctl restart tshark-capture   # Restart capture
sudo journalctl -u tshark-capture -f    # View capture logs
```

### 2. honeyd-log-sync.timer
- **Purpose**: Syncs honeyd logs to capture directory
- **Frequency**: Every 5 minutes
- **Source**: `/var/log/honeyd/`
- **Destination**: `/capture/honeyd_logs/`

**Commands**:
```bash
sudo systemctl status honeyd-log-sync.timer   # Check timer status
sudo systemctl start honeyd-log-sync.service  # Manual sync
```

## Management Scripts

### pcap-manager
Complete packet capture management tool.

**Usage**:
```bash
sudo pcap-manager list              # List all captures
sudo pcap-manager recent [N]        # Show N most recent (default: 10)
sudo pcap-manager analyze <file>    # Analyze specific pcap
sudo pcap-manager stats             # Show statistics
sudo pcap-manager clean             # Clean old captures
sudo pcap-manager stop              # Stop capture service
sudo pcap-manager start             # Start capture service
sudo pcap-manager restart           # Restart capture service
sudo pcap-manager logs              # Show honeyd logs
```

### rotate-pcap.sh
Automatically manages disk space by rotating old captures.

**Settings**:
- Maximum files: 100
- Maximum total size: 5000 MB
- Removes oldest files first

**Manual execution**:
```bash
sudo /usr/local/bin/rotate-pcap.sh
```

## Analyzing Packet Captures

### Using tshark

**View packets**:
```bash
tshark -r /capture/pcaps/capture_20251008_120000.pcap
```

**Filter by protocol**:
```bash
tshark -r /capture/pcaps/capture_20251008_120000.pcap -Y "tcp.port == 22"
tshark -r /capture/pcaps/capture_20251008_120000.pcap -Y "http"
```

**Statistics**:
```bash
tshark -r /capture/pcaps/capture_20251008_120000.pcap -q -z io,phs
```

**Export to CSV**:
```bash
tshark -r /capture/pcaps/capture_20251008_120000.pcap -T fields -E separator=, \
  -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport > output.csv
```

### Using Wireshark GUI

If you have X11 forwarding enabled or can copy files to your local machine:

```bash
# Copy file to local machine
scp vagrant@hostname:/capture/pcaps/capture_20251008_120000.pcap .

# Open with Wireshark GUI
wireshark capture_20251008_120000.pcap
```

## Disk Space Management

The system automatically manages disk space through:

1. **File rotation**: Maximum 50 active files
2. **Time-based rotation**: New file every hour
3. **Size-based cleanup**: Removes old files when total > 5GB
4. **Automatic cleanup**: Runs before each new capture starts

### Manual Cleanup

```bash
# Remove all captures older than 7 days
find /capture/pcaps -name "*.pcap" -mtime +7 -delete

# Remove all but the last 20 captures
ls -t /capture/pcaps/*.pcap | tail -n +21 | xargs rm -f

# Check disk usage
du -sh /capture/pcaps
df -h /capture
```

## Integration with Honeypot

The packet captures work alongside the honeypot to provide:

1. **Network traffic analysis**: See all packets to/from honeypot
2. **Attack forensics**: Analyze attacker techniques
3. **Protocol verification**: Verify honeypot services work correctly
4. **Traffic patterns**: Identify scanning and reconnaissance

## Monitoring

### Check Everything

```bash
sudo honeypot-status
```

This shows:
- Honeyd service status
- TShark capture status
- Recent pcap files
- Disk usage
- Log sync status

### Real-time Monitoring

**Watch captures being created**:
```bash
watch -n 5 'ls -lht /capture/pcaps/*.pcap | head -5'
```

**Monitor capture service**:
```bash
sudo journalctl -u tshark-capture -f
```

**Live packet viewing**:
```bash
sudo tshark -i any
```

## Troubleshooting

### Capture service not running

```bash
sudo systemctl status tshark-capture
sudo journalctl -u tshark-capture -n 50
sudo systemctl restart tshark-capture
```

### No pcap files created

Check permissions:
```bash
ls -ld /capture/pcaps
sudo chmod 755 /capture/pcaps
```

### Disk full

```bash
df -h /capture
sudo pcap-manager clean
```

### Missing packets

Verify interface:
```bash
ip link show
# Update tshark-capture.service to use correct interface
sudo systemctl edit tshark-capture
```

## Security Notes

1. **Permissions**: Capture directories are readable by root
2. **Sensitive data**: Pcap files may contain sensitive information
3. **Retention**: Regularly archive or remove old captures
4. **Encryption**: Consider encrypting captures at rest

## Performance Impact

- **CPU**: Minimal (< 5% on average)
- **Memory**: ~50-100 MB per tshark process
- **Disk I/O**: Moderate (depends on traffic volume)
- **Network**: No impact (passive capture)

## Best Practices

1. **Regular monitoring**: Check disk space weekly
2. **Archive old captures**: Move to long-term storage
3. **Analyze regularly**: Review captures for anomalies
4. **Keep documentation**: Note any interesting patterns
5. **Backup**: Include captures in backup strategy

## Examples

### Find SSH brute force attempts

```bash
tshark -r /capture/pcaps/*.pcap -Y "tcp.port == 22" \
  -T fields -e ip.src | sort | uniq -c | sort -rn | head
```

### Identify HTTP requests

```bash
tshark -r /capture/pcaps/*.pcap -Y "http.request" \
  -T fields -e http.request.method -e http.host -e http.request.uri
```

### Extract DNS queries

```bash
tshark -r /capture/pcaps/*.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name
```

## Additional Resources

- TShark Documentation: https://www.wireshark.org/docs/man-pages/tshark.html
- Wireshark Display Filters: https://www.wireshark.org/docs/dfref/
- PCAP Analysis Guide: https://www.wireshark.org/docs/wsug_html_chunked/
