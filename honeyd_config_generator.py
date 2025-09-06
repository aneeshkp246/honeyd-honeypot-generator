# honeyd_config_generator.py
import os, numpy as np

class HoneydConfigGenerator:
    def generate_random_honeyd_config(self, yaml_path='honeypot_pool.yaml', output_path='honeyd.conf'):
        import yaml, random
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        honeypots = data.get('honeypots', [])
        if not honeypots:
            raise ValueError('No honeypots found in YAML file.')
        hp = random.choice(honeypots)
        lines = ['# HoneyD config for a single random honeypot', '']
        template = hp['template']
        ip = hp['ip']
        os_type = hp['os']
        lines.append(f'create {template}')
        lines.append(f'set {template} personality "{os_type}"')
        lines.append(f'set {template} default tcp action reset')
        lines.append(f'set {template} default udp action reset')
        lines.append(f'set {template} default icmp action reset')
        for svc in hp['services']:
            port = svc['port']
            script_path = f"/usr/local/honeypot/scripts/{svc['name']}_script.py"
            lines.append(f'add {template} tcp port {port} "python3 {script_path}"')
        lines.append(f'bind {ip} {template}')
        lines.append('')
        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        print(f'Random honeypot config written to {output_path} for IP {ip}')
    def get_banner(self, svc):
        banners = {
            'http': 'HTTP/1.1 200 OK',
            'ssh': 'SSH-2.0-OpenSSH_7.4',
            'ftp': '220 FTP Server ready',
            'dns': 'DNS honeypot',
            'telnet': 'Welcome to telnet',
            'smtp': '220 smtp honeypot',
            'pop3': '+OK POP3 ready',
            'imap': '* OK IMAP4 ready',
            'snmp': 'SNMP honeypot',
            'https': 'HTTP/1.1 200 OK',
        }
        return banners.get(svc, f'{svc} honeypot placeholder')
    def __init__(self):
        self.service_ports = {
            'http': 80,
            'https': 443,
            'ssh': 22,
            'ftp': 21,
            'smtp': 25,
            'dns': 53,
            'telnet': 23,
            'pop3': 110,
            'imap': 143,
            'snmp': 161
        }
        self.os_templates = [
            'Linux 2.6.x','Windows XP','Windows 7','Windows 10','FreeBSD','OpenBSD','Solaris'
        ]

    def _extract_services(self, config_vec):
        v = np.array(config_vec, dtype=float)
        if np.max(v) - np.min(v) == 0:
            vn = np.zeros_like(v)
        else:
            vn = (v - np.min(v)) / (np.max(v) - np.min(v))
        service_list = list(self.service_ports.keys())
        chosen = {}
        top_idx = np.argsort(-vn)[:4]
        for idx in top_idx:
            svc = service_list[idx % len(service_list)]
            if vn[idx] > 0.05:
                chosen[svc] = self.service_ports[svc]
        if not chosen:
            chosen['http'] = 80
        return chosen

    def generate_honeyd_config_from_yaml(self, yaml_path='honeypot_pool.yaml'):
        import yaml
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        lines = ['# HoneyD config generated from YAML pool', '']
        for hp in data.get('honeypots', []):
            template = hp['template']
            ip = hp['ip']
            os_type = hp['os']
            lines.append(f'create {template}')
            lines.append(f'set {template} personality "{os_type}"')
            lines.append(f'set {template} default tcp action reset')
            lines.append(f'set {template} default udp action reset')
            lines.append(f'set {template} default icmp action reset')
            for svc in hp['services']:
                port = svc['port']
                script_path = f"/usr/local/honeypot/scripts/{svc['name']}_script.py"
                lines.append(f'add {template} tcp port {port} "python3 {script_path}"')
            lines.append(f'bind {ip} {template}')
            lines.append('')
        return '\n'.join(lines)

    def generate_honeypot_scripts(self, services, output_dir='honeypot_scripts'):
        os.makedirs(output_dir, exist_ok=True)
        log_dir = os.path.join('.', 'log', 'honeyd')
        os.makedirs(log_dir, exist_ok=True)
        for s in services:
            if s == 'http':
                code = '''#!/usr/bin/env python3
print("HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body><h1>OK</h1></body></html>")
            with open(r'{os.path.join(log_dir, "http.log")}','a') as f:
    f.write("http hit\n")
'''
            elif s == 'ssh':
                code = '''#!/usr/bin/env python3
print("SSH-2.0-OpenSSH_7.4\r\n")
            with open(r'{os.path.join(log_dir, "ssh.log")}','a') as f:
    f.write("ssh attempt\n")
'''
            else:
                code = f'''#!/usr/bin/env python3
print("{s} honeypot placeholder")
            with open(r'{os.path.join(log_dir, f"{s}.log")}','a') as f:
    f.write("{s} connection\n")
'''
            path = os.path.join(output_dir, f"{s}_script.py")
            with open(path, 'w') as fh:
                fh.write(code)
            os.chmod(path, 0o755)
