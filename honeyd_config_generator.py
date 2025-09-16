# honeyd_config_generator.py
import os
import numpy as np
import yaml  # Add this import
import random  # Add this import

class HoneydConfigGenerator:
    def __init__(self):
        # Core TCP/UDP services and well-known ports
        self.service_ports = {
            'http': 80,
            'https': 443,
            'ssh': 22,
            'ftp': 21,
            'smtp': 25,
            'dns': 53,      # also UDP
            'telnet': 23,
            'pop3': 110,
            'imap': 143,
            'snmp': 161,    # also UDP
        }
        # Extra commonly scanned/attacked services (mix TCP/UDP)
        self.extra_service_ports = {
            'ntp': 123,     # UDP
            'ldap': 389,
            'rdp': 3389,
            'mssql': 1433,
            'redis': 6379,
            'memcached': 11211,  # mostly UDP/TCP
            'mysql': 3306,
            'postgres': 5432,
            'rdp-3389': 3389
        }
        self.os_templates = [
            'Linux 2.6.x', 'Windows XP', 'Windows 7', 'Windows 10', 'FreeBSD', 'OpenBSD', 'Solaris'
        ]

    def get_banner(self, svc):
        banners = {
            'http': 'HTTP/1.1 200 OK',
            'https': 'HTTP/1.1 200 OK',
            'ssh': 'SSH-2.0-OpenSSH_7.9',
            'ftp': '220 FTP Server ready',
            'dns': 'DNS honeypot',
            'telnet': 'Welcome to telnet',
            'smtp': '220 smtp honeypot',
            'pop3': '+OK POP3 ready',
            'imap': '* OK IMAP4 ready',
            'snmp': 'SNMP honeypot',
            'ntp': 'NTP honeypot',
            'ldap': 'LDAP honeypot',
            'rdp': 'RDP honeypot',
            'mssql': 'MSSQL honeypot',
            'redis': '-ERR unknown command',
            'memcached': 'VERSION 1.5.22',
            'mysql': '5.7.31',
            'postgres': 'PostgreSQL 12.4'
        }
        return banners.get(svc, f'{svc} honeypot placeholder')

    def _extract_services(self, config_vec):
        # Backward-compatible selector: choose top-K services from base set
        v = np.array(config_vec, dtype=float)
        if np.max(v) - np.min(v) == 0:
            vn = np.zeros_like(v)
        else:
            vn = (v - np.min(v)) / (np.max(v) - np.min(v))
        service_list = list(self.service_ports.keys())
        chosen = {}
        top_idx = np.argsort(-vn)[:6]
        for idx in top_idx:
            svc = service_list[idx % len(service_list)]
            if vn[idx] > 0.05:
                chosen[svc] = self.service_ports[svc]
        if not chosen:
            chosen['http'] = 80
        return chosen

    def generate_honeyd_config_from_yaml(self, yaml_path='honeypot_pool.yaml'):
        """
        Build a honeyd.conf from honeypot_pool.yaml.
        Adds multiple TCP and selected UDP services.
        Injects env vars RATE, SIZE, ERR for scripts (from TimeGAN).
        """
        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        lines = ['# HoneyD config generated from YAML pool', '']
        for hp in data.get('honeypots', []):
            template = hp['template']
            ip = hp['ip']
            os_type = hp['os']
            dropr_in = float(hp.get('droprate_in', 0.0))
            dropr_syn = float(hp.get('droprate_syn', 0.0))

            lines.append(f'create {template}')
            lines.append(f'set {template} personality "{os_type}"')
            lines.append(f'set {template} default tcp action reset')
            lines.append(f'set {template} default udp action reset')
            lines.append(f'set {template} default icmp action reset')
            if dropr_in > 0:
                lines.append(f'set {template} droprate in {dropr_in:.2f}')
            if dropr_syn > 0:
                lines.append(f'set {template} droprate syn {dropr_syn:.2f}')

            for svc in hp.get('services', []):
                name = svc['name']
                port = int(svc['port'])
                script_path = f"/usr/local/honeypot/scripts/{name}_script.py"
                # Pass behavior parameters derived from TimeGAN
                env_vars = f'RATE={svc.get("rate",5)} SIZE={svc.get("avg_size",500)} ERR={svc.get("err_prob",0.05)}'
                # TCP binding
                lines.append(f'add {template} tcp port {port} "{env_vars} python3 {script_path}"')
                # UDP for relevant services
                if name in ['dns','ntp','snmp','memcached','redis']:
                    lines.append(f'add {template} udp port {port} "{env_vars} python3 {script_path}"')

            lines.append(f'bind {ip} {template}')
            lines.append('')

        return '\n'.join(lines)

    def generate_random_honeyd_config(self, yaml_path='honeypot_pool.yaml', output_path='honeyd.conf'):
        """
        For quick testing: pick one honeypot and render its config.
        """
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

        for svc in hp.get('services', []):
            name = svc['name']
            port = int(svc['port'])
            script_path = f"/usr/local/honeypot/scripts/{name}_script.py"
            env_vars = f'RATE={svc.get("rate",5)} SIZE={svc.get("avg_size",500)} ERR={svc.get("err_prob",0.05)}'
            lines.append(f'add {template} tcp port {port} "{env_vars} python3 {script_path}"')
            if name in ['dns','ntp','snmp','memcached','redis']:
                lines.append(f'add {template} udp port {port} "{env_vars} python3 {script_path}"')

        lines.append(f'bind {ip} {template}')
        lines.append('')

        with open(output_path, 'w') as f:
            f.write('\n'.join(lines))
        print(f'Random honeypot config written to {output_path} for IP {ip}')

    def generate_honeypot_scripts(self, services, output_dir='honeypot_scripts'):
        """
        Emit simple but richer protocol scripts.
        Each script reads RATE, SIZE, ERR env vars, responds, and logs JSON lines.
        """
        os.makedirs(output_dir, exist_ok=True)
        log_dir = os.path.join('.', 'log', 'honeyd')
        os.makedirs(log_dir, exist_ok=True)

        def base_script_proto(name, body):
            return f'''#!/usr/bin/env python3
import os, sys, time, json, random
RATE = float(os.getenv("RATE","5"))
AVG_SIZE = float(os.getenv("SIZE","500"))
ERR = float(os.getenv("ERR","0.05"))
DELAY = max(0.01, 1.0/(RATE+1e-6))  # inter-arrival proxy
LOGF = os.path.join(".", "log", "honeyd", "{name}.log")
def log(event, extra=None):
    try:
        with open(LOGF, "a") as f:
            f.write(json.dumps({{"ts": time.time(), "event": event, **(extra or {{}})}}) + "\\n")
    except Exception:
        pass
def maybe_fail():
    return random.random() < ERR
def main():
    log("start", {{"rate": RATE, "avg_size": AVG_SIZE, "err": ERR}})
{body}
if __name__ == "__main__":
    main()
'''

        scripts = {}

        # HTTP
        scripts['http'] = base_script_proto('http', '''
    try:
        # Minimal HTTP 200 page
        body = "<html><body><h1>It works</h1></body></html>"
        if maybe_fail():
            sys.stdout.write("HTTP/1.1 500 Internal Server Error\\r\\nContent-Length: 0\\r\\n\\r\\n")
            log("http_500", {{"size": 0}})
        else:
            sys.stdout.write("HTTP/1.1 200 OK\\r\\nServer: mini\\r\\nContent-Type: text/html\\r\\nContent-Length: {}\\r\\n\\r\\n".format(len(body)))
            sys.stdout.write(body)
            log("http_200", {{"size": len(body)}})
        sys.stdout.flush()
        time.sleep(DELAY)
    except Exception as e:
        log("error", {{"err": str(e)}})
''')

        # HTTPS (banner-like, not TLS)
        scripts['https'] = base_script_proto('https', '''
    sys.stdout.write("HTTP/1.1 200 OK\\r\\nServer: tls-proxy\\r\\nContent-Length: 0\\r\\n\\r\\n")
    sys.stdout.flush()
    log("https_resp", {{"size": 0}})
    time.sleep(DELAY)
''')

        # SSH
        scripts['ssh'] = base_script_proto('ssh', '''
    sys.stdout.write("SSH-2.0-OpenSSH_7.9\\r\\n")
    sys.stdout.flush()
    log("ssh_banner", None)
    # Fake authentication prompt cycle
    prompts = 1 + int(RATE) % 3
    for i in range(prompts):
        sys.stdout.write("Password: \\r\\n")
        sys.stdout.flush()
        time.sleep(DELAY)
        log("ssh_auth_prompt", {{"idx": i}})
    log("ssh_disconnect", None)
''')

        # FTP
        scripts['ftp'] = base_script_proto('ftp', '''
    sys.stdout.write("220 FTP Server ready\\r\\n")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("331 Please specify the password.\\r\\n")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("230 Login successful.\\r\\n")
    sys.stdout.flush()
    log("ftp_login", None)
''')

        # DNS (UDP/TCP)
        scripts['dns'] = base_script_proto('dns', '''
    # Respond with fixed A record-like line (not real DNS)
    resp = "DNS honeypot response\\n"
    sys.stdout.write(resp)
    sys.stdout.flush()
    log("dns_resp", {{"size": len(resp)}})
    time.sleep(DELAY)
''')

        # SMTP
        scripts['smtp'] = base_script_proto('smtp', '''
    sys.stdout.write("220 smtp honeypot\\r\\n")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("250 OK\\r\\n")
    sys.stdout.flush()
    log("smtp_ok", None)
''')

        # TELNET
        scripts['telnet'] = base_script_proto('telnet', '''
    sys.stdout.write("Welcome to telnet\\r\\nlogin: ")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("Password: \\r\\n")
    sys.stdout.flush()
    log("telnet_prompt", None)
''')

        # POP3
        scripts['pop3'] = base_script_proto('pop3', '''
    sys.stdout.write("+OK POP3 ready\\r\\n")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("+OK 0 messages\\r\\n")
    sys.stdout.flush()
    log("pop3_ready", None)
''')

        # IMAP
        scripts['imap'] = base_script_proto('imap', '''
    sys.stdout.write("* OK IMAP4 ready\\r\\n")
    sys.stdout.flush()
    time.sleep(DELAY)
    sys.stdout.write("a001 OK LOGIN completed\\r\\n")
    sys.stdout.flush()
    log("imap_login", None)
''')

        # SNMP
        scripts['snmp'] = base_script_proto('snmp', '''
    sys.stdout.write("SNMP honeypot\\n")
    sys.stdout.flush()
    log("snmp_resp", None)
    time.sleep(DELAY)
''')

        # NTP
        scripts['ntp'] = base_script_proto('ntp', '''
    sys.stdout.write("NTP honeypot\\n")
    sys.stdout.flush()
    log("ntp_resp", None)
    time.sleep(DELAY)
''')

        # LDAP
        scripts['ldap'] = base_script_proto('ldap', '''
    sys.stdout.write("LDAP honeypot\\n")
    sys.stdout.flush()
    log("ldap_resp", None)
    time.sleep(DELAY)
''')

        # RDP
        scripts['rdp'] = base_script_proto('rdp', '''
    sys.stdout.write("RDP honeypot\\n")
    sys.stdout.flush()
    log("rdp_resp", None)
    time.sleep(DELAY)
''')

        # MSSQL
        scripts['mssql'] = base_script_proto('mssql', '''
    sys.stdout.write("MSSQL honeypot\\n")
    sys.stdout.flush()
    log("mssql_resp", None)
    time.sleep(DELAY)
''')

        # Redis
        scripts['redis'] = base_script_proto('redis', '''
    sys.stdout.write("-ERR unknown command\\r\\n")
    sys.stdout.flush()
    log("redis_err", None)
    time.sleep(DELAY)
''')

        # Memcached
        scripts['memcached'] = base_script_proto('memcached', '''
    sys.stdout.write("VERSION 1.5.22\\r\\n")
    sys.stdout.flush()
    log("memcached_version", None)
    time.sleep(DELAY)
''')

        # MySQL
        scripts['mysql'] = base_script_proto('mysql', '''
    sys.stdout.write("5.7.31\\r\\n")
    sys.stdout.flush()
    log("mysql_banner", None)
    time.sleep(DELAY)
''')

        # PostgreSQL
        scripts['postgres'] = base_script_proto('postgres', '''
    sys.stdout.write("PostgreSQL 12.4\\r\\n")
    sys.stdout.flush()
    log("postgres_banner", None)
    time.sleep(DELAY)
''')

        # Write scripts
        for name in services:
            code = scripts.get(name)
            if not code:
                # default generic script
                code = base_script_proto(name, f'''
    sys.stdout.write("{name} honeypot\\n")
    sys.stdout.flush()
    log("{name}_resp", None)
    time.sleep(DELAY)
''')
            path = os.path.join(output_dir, f'{name}_script.py')
            with open(path, 'w') as f:
                f.write(code)
            try:
                os.chmod(path, 0o755)
            except Exception:
                pass

    # Legacy helper: single random config writer (kept for compatibility)
    def generate_random_honeyd_config(self, yaml_path='honeypot_pool.yaml', output_path='honeyd.conf'):
        return self.generate_random_honeyd_config(yaml_path, output_path)

    def generate_random_honeyd_config(self, yaml_path, output_path):
        """
        Generate a random honeyd configuration from the honeypot pool
        and write it to the specified output file.
        """
        # Load honeypots from YAML
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

        for svc in hp.get('services', []):
            name = svc['name']
            port = int(svc['port'])
            script_path = f"/usr/local/honeypot/scripts/{name}_script.py"
            env_vars = f'RATE={svc.get("rate",5)} SIZE={svc.get("avg_size",500)} ERR={svc.get("err_prob",0.05)}'
            lines.append(f'add {template} tcp port {port} "{env_vars} python3 {script_path}"')
            if name in ['dns','ntp','snmp','memcached','redis']:
                lines.append(f'add {template} udp port {port} "{env_vars} python3 {script_path}"')

        lines.append(f'bind {ip} {template}')
        lines.append('')

        config_content = '\n'.join(lines)
        
        # Write to output file
        with open(output_path, 'w') as f:
            f.write(config_content)
            
        print(f'Random honeypot config written to {output_path} for IP {ip}')
        return config_content
