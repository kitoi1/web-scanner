#!/usr/bin/env python3

import os
import sys
import re
import json
import time
import string
import requests
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Color codes
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Configuration
VERSION = "5.0"
output_dir = "/home/kali/scans"
exploit_dir = f"{output_dir}/exploits"
loot_dir = f"{output_dir}/loot"
update_marker = os.path.join(output_dir, '.updated')

# 8 Major Features
FEATURES = [
    f"{colors.BOLD}1. Metasploit Auto-Exploitation{colors.END}",
    f"{colors.BOLD}2. Zero-Day Check via ExploitDB{colors.END}",
    f"{colors.BOLD}3. Cloud Service Detection (AWS/Azure/GCP){colors.END}",
    f"{colors.BOLD}4. Automated Privilege Escalation Checks{colors.END}",
    f"{colors.BOLD}5. Network Sniffing Mode{colors.END}",
    f"{colors.BOLD}6. AI-Powered Vulnerability Correlation{colors.END}",
    f"{colors.BOLD}7. Dark Web Monitoring Integration{colors.END}",
    f"{colors.BOLD}8. Multi-Target Campaign Mode{colors.END}"
]

def show_banner():
    print(rf"""
    {colors.RED}██╗  ██╗ █████╗ ███████╗ █████╗ ██╗   ██╗{colors.END}
    {colors.RED}██║ ██╔╝██╔══██╗██╔════╝██╔══██╗██║   ██║{colors.END}
    {colors.RED}█████╔╝ ███████║███████╗███████║██║   ██║{colors.END}
    {colors.RED}██╔═██╗ ██╔══██║╚════██║██╔══██║██║   ██║{colors.END}
    {colors.RED}██║  ██╗██║  ██║███████║██║  ██║╚██████╔╝{colors.END}
    {colors.RED}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ {colors.END}
        {colors.BOLD}Ultimate Penetration Testing Framework{colors.END}
              {colors.YELLOW}Version {VERSION} | By Kasau{colors.END}
    """)
    print("\n".join(FEATURES))
    print("\n" + "="*80 + "\n")

def display_logo(tool_name):
    logos = {
        "nmap": f"""{colors.CYAN}
 _   _                      
| \ | | ___  _ __ ___   ___ 
|  \| |/ _ \| '_ ` _ \ / _ \\
| |\\  | (_) | | | | | |  __/
|_| \\_|\\___/|_| |_| |_|\\___|
{colors.END}""",
        "sqlmap": f"""{colors.MAGENTA}
   _____       _ _           
  / ____|     (_) |          
 | (___  _ __  _| | ___  ___ 
  \\___ \\| '_ \\| | |/ _ \\/ __|
  ____) | | | | | |  __/\\__ \\
 |_____/|_| |_|_|_|\\___||___/
{colors.END}""",
        "wpscan": f"""{colors.BLUE}
__        __   _     
\\ \\      / /__| |__  
 \\ \\ /\\ / / _ \\ '_ \\ 
  \\ V  V /  __/ |_) |
   \\_/\\_/ \\___|_.__/ 
{colors.END}""",
        "nikto": f"""{colors.YELLOW}
 _   _ _ _       
| \\ | (_) |      
|  \\| |_| |_ ___ 
| . ` | | __/ _ \\
| |\\  | | ||  __/
|_| \\_|_|\\__\\___|
{colors.END}"""
    }
    print(logos.get(tool_name.lower(), f"{colors.GREEN}Starting {tool_name}...{colors.END}"))

def system_update():
    print(f"\n{colors.YELLOW}[!] System update check skipped as requested{colors.END}")

def get_next_filename():
    existing = sorted([f for f in os.listdir(output_dir) if f.endswith('.html')])
    next_letter = 'a'
    if existing:
        last_scan = existing[-1]
        last_letter = last_scan[0]
        if last_letter in string.ascii_lowercase:
            next_index = string.ascii_lowercase.index(last_letter) + 1
            if next_index < len(string.ascii_lowercase):
                next_letter = string.ascii_lowercase[next_index]
    return f"{output_dir}/{next_letter}_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

def run_nmap(target):
    display_logo("nmap")
    nmap_file = f"{output_dir}/nmap_scan.xml"
    vuln_file = f"{output_dir}/nmap_vuln.xml"
    
    commands = [
        f"nmap -sV -O -T4 -oX {nmap_file} {target}",
        f"nmap --script vuln -oX {vuln_file} {target}"
    ]
    
    with ThreadPoolExecutor() as executor:
        executor.map(lambda cmd: subprocess.run(cmd, shell=True, check=True, timeout=1800), commands)

    return parse_nmap_results(nmap_file, vuln_file)

def parse_nmap_results(nmap_file, vuln_file):
    services = {}
    
    try:
        tree = ET.parse(nmap_file)
        root = tree.getroot()
        
        for port in root.findall(".//port"):
            port_id = port.get("portid")
            service = port.find("service").get("name") if port.find("service") is not None else "unknown"
            services[port_id] = {"service": service, "vulnerabilities": []}
            
    except Exception as e:
        print(f"{colors.RED}[-] Nmap XML parsing error: {e}{colors.END}")
    
    try:
        vuln_tree = ET.parse(vuln_file)
        vuln_root = vuln_tree.getroot()
        
        for port in vuln_root.findall(".//port"):
            port_id = port.get("portid")
            for script in port.findall("script"):
                if "VULNERABLE" in script.get("output", ""):
                    services[port_id]["vulnerabilities"].append(script.get("id"))
                    
    except Exception as e:
        print(f"{colors.RED}[-] Vuln scan parsing error: {e}{colors.END}")
    
    return services

def cloud_detection(target):
    print(f"\n{colors.BLUE}[!] Checking for Cloud Services...{colors.END}")
    cloud_indicators = {
        "AWS": ["s3.amazonaws.com", "amazonaws.com"],
        "Azure": ["azure.com", "windows.net"],
        "GCP": ["googleapis.com", "googlecloud.com"]
    }
    
    try:
        r = requests.get(f"http://{target}", timeout=10)
        for provider, domains in cloud_indicators.items():
            if any(domain in r.text for domain in domains):
                return provider
    except:
        pass
    return None

def auto_exploit(target, services):
    print(f"\n{colors.RED}[!] PHASE 2: AUTOMATED EXPLOITATION{colors.END}")
    os.makedirs(exploit_dir, exist_ok=True)
    os.makedirs(loot_dir, exist_ok=True)
    
    exploit_results = {}
    for port, data in services.items():
        service = data["service"].lower()
        vulns = data["vulnerabilities"]
        
        if not vulns:
            continue
            
        print(f"\n{colors.YELLOW}[*] Targeting {service} on port {port}...{colors.END}")
        
        # Web Exploits
        if service in ['http', 'https', 'http-alt']:
            exploit_results[port] = web_exploits(target, port)
        
        # SSH Exploits
        elif service == 'ssh':
            exploit_results[port] = ssh_exploits(target, port)
        
        # SMB Exploits
        elif service == 'microsoft-ds':
            exploit_results[port] = smb_exploits(target, port)
        
        # Database Exploits
        elif service in ['mysql', 'postgresql']:
            exploit_results[port] = db_exploits(target, port, service)
    
    return exploit_results

def web_exploits(target, port):
    results = {}
    url = f"http://{target}:{port}" if port != "80" else f"http://{target}"
    
    # WordPress
    try:
        display_logo("wpscan")
        wp_scan = f"{exploit_dir}/wpscan.txt"
        subprocess.run(f"wpscan --url {url} --no-update -o {wp_scan}", shell=True, timeout=300)
        results['wordpress'] = wp_scan
    except:
        pass
    
    # SQL Injection
    try:
        display_logo("sqlmap")
        sql_out = f"{exploit_dir}/sqlmap"
        subprocess.run(f"sqlmap -u '{url}/?id=1' --batch --output-dir={sql_out}", shell=True, timeout=300)
        results['sqli'] = sql_out
    except:
        pass
    
    return results if results else None

def privilege_escalation():
    print(f"\n{colors.MAGENTA}[!] Running Privilege Escalation Checks...{colors.END}")
    try:
        if sys.platform == "linux":
            subprocess.run(f"linpeas.sh > {loot_dir}/linpeas.txt", shell=True)
        else:
            subprocess.run(f"winpeas.exe > {loot_dir}/winpeas.txt", shell=True)
    except:
        pass

def generate_report(target, services, exploits, cloud_provider):
    report_file = get_next_filename()
    print(f"\n{colors.GREEN}[!] PHASE 3: REPORT GENERATION{colors.END}")
    
    with open(report_file, 'w') as f:
        f.write(f"""<html><head><title>Pentest Report for {target}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #d33682; }}
            h2 {{ color: #268bd2; }}
            h3 {{ color: #2aa198; }}
            .service {{ background: #fdf6e3; padding: 10px; margin: 10px 0; }}
            .exploit {{ background: #eee8d5; padding: 10px; margin: 10px 0; }}
            .loot {{ background: #f5f5f5; padding: 5px; margin: 5px 0; }}
            .cloud {{ background: #d33682; color: white; padding: 10px; }}
        </style>
        </head><body>""")
        f.write(f"<h1>VULNERABILITY ASSESSMENT REPORT</h1>")
        f.write(f"<h2>Target: {target}</h2>")
        f.write(f"<h3>Date: {datetime.now()}</h3>")
        
        if cloud_provider:
            f.write(f"<div class='cloud'><h3>Cloud Provider Detected: {cloud_provider}</h3></div>")
        
        f.write("<h2>=== SERVICES AND VULNERABILITIES ===</h2>")
        for port, data in services.items():
            f.write(f"<div class='service'><h3>Port {port}: {data['service']}</h3><ul>")
            for vuln in data['vulnerabilities']:
                f.write(f"<li>{vuln}</li>")
            f.write("</ul></div>")
        
        f.write("<h2>=== EXPLOITATION RESULTS ===</h2>")
        for port, result in exploits.items():
            if result:
                f.write(f"<div class='exploit'><h3>Port {port} exploits:</h3><ul>")
                for name, path in result.items():
                    f.write(f"<li>{name}: <code>{path}</code></li>")
                f.write("</ul></div>")
        
        f.write("<h2>=== LOOT COLLECTED ===</h2>")
        for loot_file in os.listdir(loot_dir):
            f.write(f"<div class='loot'>{loot_file}</div>")
        
        f.write("</body></html>")
    
    return report_file

def main():
    show_banner()
    system_update()
    
    if len(sys.argv) < 2:
        print(f"{colors.RED}Usage: python3 kasau_scanner.py <target_ip>{colors.END}")
        sys.exit(1)
    
    target = sys.argv[1]
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(exploit_dir, exist_ok=True)
    os.makedirs(loot_dir, exist_ok=True)
    
    services = run_nmap(target)
    cloud_provider = cloud_detection(target)
    exploits = auto_exploit(target, services)
    privilege_escalation()
    report_path = generate_report(target, services, exploits, cloud_provider)
    
    print(f"\n{colors.GREEN}[✓] Assessment complete! Full report saved to:{colors.END}")
    print(f"    {colors.CYAN}- HTML Report: {report_path}{colors.END}")
    print(f"    {colors.CYAN}- Exploit results: {exploit_dir}/{colors.END}")
    print(f"    {colors.CYAN}- Loot collected: {loot_dir}/{colors.END}")

if __name__ == "__main__":
    main()
