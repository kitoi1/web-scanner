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
    f"{colors.BOLD}1. Network Discovery & Port Scanning{colors.END}",
    f"{colors.BOLD}2. Vulnerability Assessment{colors.END}",
    f"{colors.BOLD}3. Cloud Service Detection (AWS/Azure/GCP){colors.END}",
    f"{colors.BOLD}4. Web Application Testing{colors.END}",
    f"{colors.BOLD}5. Service Enumeration{colors.END}",
    f"{colors.BOLD}6. Security Configuration Analysis{colors.END}",
    f"{colors.BOLD}7. Compliance Checking{colors.END}",
    f"{colors.BOLD}8. Comprehensive Reporting{colors.END}"
]

def show_banner():
    # Fixed the raw string formatting to avoid SyntaxWarning
    print(f"""
    {colors.RED}██╗  ██╗ █████╗ ███████╗ █████╗ ██╗   ██╗{colors.END}
    {colors.RED}██║ ██╔╝██╔══██╗██╔════╝██╔══██╗██║   ██║{colors.END}
    {colors.RED}█████╔╝ ███████║███████╗███████║██║   ██║{colors.END}
    {colors.RED}██╔═██╗ ██╔══██║╚════██║██╔══██║██║   ██║{colors.END}
    {colors.RED}██║  ██╗██║  ██║███████║██║  ██║╚██████╔╝{colors.END}
    {colors.RED}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ {colors.END}
        {colors.BOLD}Security Assessment Framework{colors.END}
              {colors.YELLOW}Version {VERSION} | Authorized Testing Only{colors.END}
    """)
    print("\n".join(FEATURES))
    print("\n" + "="*80 + "\n")

def display_logo(tool_name):
    # Fixed escape sequences
    logos = {
        "nmap": f"""{colors.CYAN}
 _   _                      
| \\ | | ___  _ __ ___   ___ 
|  \\| |/ _ \\| '_ ` _ \\ / _ \\
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

def check_dependencies():
    """Check if required tools are installed"""
    required_tools = ['nmap', 'wpscan', 'sqlmap', 'nikto']
    missing_tools = []
    
    for tool in required_tools:
        if subprocess.run(f"which {tool}", shell=True, capture_output=True).returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{colors.RED}[!] Missing required tools: {', '.join(missing_tools)}{colors.END}")
        print(f"{colors.YELLOW}[!] Please install missing tools before running this script{colors.END}")
        return False
    return True

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
    
    print(f"{colors.YELLOW}[*] Running port scan on {target}...{colors.END}")
    
    try:
        # Basic port scan
        cmd1 = f"nmap -sV -O -T4 -oX {nmap_file} {target}"
        result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True, timeout=1800)
        
        if result1.returncode != 0:
            print(f"{colors.RED}[-] Nmap scan failed: {result1.stderr}{colors.END}")
            return {}
        
        print(f"{colors.YELLOW}[*] Running vulnerability scan...{colors.END}")
        
        # Vulnerability scan
        cmd2 = f"nmap --script vuln -oX {vuln_file} {target}"
        result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True, timeout=1800)
        
        if result2.returncode != 0:
            print(f"{colors.RED}[-] Nmap vuln scan failed: {result2.stderr}{colors.END}")
        
    except subprocess.TimeoutExpired:
        print(f"{colors.RED}[-] Nmap scan timed out{colors.END}")
        return {}
    except Exception as e:
        print(f"{colors.RED}[-] Nmap scan error: {e}{colors.END}")
        return {}

    return parse_nmap_results(nmap_file, vuln_file)

def parse_nmap_results(nmap_file, vuln_file):
    services = {}
    
    try:
        if os.path.exists(nmap_file):
            tree = ET.parse(nmap_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                for port in host.findall('.//port'):
                    port_id = port.get("portid")
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        service_elem = port.find("service")
                        service = service_elem.get("name") if service_elem is not None else "unknown"
                        version = service_elem.get("version", "") if service_elem is not None else ""
                        services[port_id] = {
                            "service": service, 
                            "version": version,
                            "vulnerabilities": []
                        }
        else:
            print(f"{colors.RED}[-] Nmap scan file not found: {nmap_file}{colors.END}")
            
    except Exception as e:
        print(f"{colors.RED}[-] Nmap XML parsing error: {e}{colors.END}")
    
    try:
        if os.path.exists(vuln_file):
            vuln_tree = ET.parse(vuln_file)
            vuln_root = vuln_tree.getroot()
            
            for host in vuln_root.findall('host'):
                for port in host.findall('.//port'):
                    port_id = port.get("portid")
                    if port_id in services:
                        for script in port.findall('script'):
                            script_output = script.get("output", "")
                            if "VULNERABLE" in script_output or "CVE" in script_output:
                                services[port_id]["vulnerabilities"].append({
                                    "script": script.get("id"),
                                    "output": script_output
                                })
        else:
            print(f"{colors.RED}[-] Vuln scan file not found: {vuln_file}{colors.END}")
                    
    except Exception as e:
        print(f"{colors.RED}[-] Vuln scan parsing error: {e}{colors.END}")
    
    return services

def cloud_detection(target):
    print(f"\n{colors.BLUE}[!] Checking for Cloud Services...{colors.END}")
    cloud_indicators = {
        "AWS": ["s3.amazonaws.com", "amazonaws.com", "aws.com"],
        "Azure": ["azure.com", "windows.net", "azurewebsites.net"],
        "GCP": ["googleapis.com", "googlecloud.com", "gcp.com"]
    }
    
    detected_providers = []
    
    try:
        # Check HTTP headers and content
        for protocol in ['http', 'https']:
            try:
                url = f"{protocol}://{target}"
                r = requests.get(url, timeout=10, allow_redirects=True)
                
                # Check headers
                headers_str = str(r.headers).lower()
                content_str = r.text.lower()
                
                for provider, domains in cloud_indicators.items():
                    if any(domain in headers_str or domain in content_str for domain in domains):
                        if provider not in detected_providers:
                            detected_providers.append(provider)
                            
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"{colors.RED}[-] Cloud detection error: {e}{colors.END}")
    
    return detected_providers

def web_security_scan(target, port):
    """Perform web application security scanning"""
    results = {}
    
    if port in ['80', '443', '8080', '8443']:
        protocol = 'https' if port in ['443', '8443'] else 'http'
        url = f"{protocol}://{target}:{port}" if port not in ['80', '443'] else f"{protocol}://{target}"
        
        print(f"{colors.YELLOW}[*] Scanning web application at {url}...{colors.END}")
        
        # Nikto scan
        try:
            display_logo("nikto")
            nikto_out = f"{exploit_dir}/nikto_{port}.txt"
            cmd = f"nikto -h {url} -output {nikto_out}"
            subprocess.run(cmd, shell=True, timeout=600, capture_output=True)
            if os.path.exists(nikto_out):
                results['nikto'] = nikto_out
                print(f"{colors.GREEN}[+] Nikto scan completed: {nikto_out}{colors.END}")
        except subprocess.TimeoutExpired:
            print(f"{colors.RED}[-] Nikto scan timed out{colors.END}")
        except Exception as e:
            print(f"{colors.RED}[-] Nikto scan error: {e}{colors.END}")
        
        # WordPress scan (if WordPress is detected)
        try:
            r = requests.get(url, timeout=10)
            if 'wp-content' in r.text or 'wordpress' in r.text.lower():
                display_logo("wpscan")
                wp_scan = f"{exploit_dir}/wpscan_{port}.txt"
                cmd = f"wpscan --url {url} --no-update -o {wp_scan}"
                subprocess.run(cmd, shell=True, timeout=600, capture_output=True)
                if os.path.exists(wp_scan):
                    results['wordpress'] = wp_scan
                    print(f"{colors.GREEN}[+] WordPress scan completed: {wp_scan}{colors.END}")
        except Exception as e:
            print(f"{colors.RED}[-] WordPress detection error: {e}{colors.END}")
    
    return results if results else None

def security_assessment(target, services):
    """Perform security assessment on discovered services"""
    print(f"\n{colors.BLUE}[!] PHASE 2: SECURITY ASSESSMENT{colors.END}")
    os.makedirs(exploit_dir, exist_ok=True)
    os.makedirs(loot_dir, exist_ok=True)
    
    assessment_results = {}
    
    for port, data in services.items():
        service = data["service"].lower()
        
        print(f"\n{colors.YELLOW}[*] Assessing {service} on port {port}...{colors.END}")
        
        # Web services
        if service in ['http', 'https', 'http-alt', 'http-proxy']:
            assessment_results[port] = web_security_scan(target, port)
        
        # SSH services
        elif service == 'ssh':
            assessment_results[port] = ssh_assessment(target, port)
        
        # Database services
        elif service in ['mysql', 'postgresql', 'mssql']:
            assessment_results[port] = db_assessment(target, port, service)
    
    return assessment_results

def ssh_assessment(target, port):
    """Assess SSH service security"""
    results = {}
    
    try:
        # Check SSH configuration
        ssh_audit_out = f"{exploit_dir}/ssh_audit_{port}.txt"
        cmd = f"ssh-audit {target} -p {port}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        with open(ssh_audit_out, 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        
        results['ssh_audit'] = ssh_audit_out
        print(f"{colors.GREEN}[+] SSH audit completed: {ssh_audit_out}{colors.END}")
        
    except Exception as e:
        print(f"{colors.RED}[-] SSH assessment error: {e}{colors.END}")
    
    return results if results else None

def db_assessment(target, port, service):
    """Assess database service security"""
    results = {}
    
    try:
        # Basic connection test
        db_test_out = f"{exploit_dir}/{service}_test_{port}.txt"
        
        if service == 'mysql':
            cmd = f"mysql -h {target} -P {port} -u root --connect-timeout=10 -e 'SELECT VERSION();'"
        elif service == 'postgresql':
            cmd = f"psql -h {target} -p {port} -U postgres -c 'SELECT version();'"
        else:
            return None
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        
        with open(db_test_out, 'w') as f:
            f.write(f"Command: {cmd}\n")
            f.write(f"Return code: {result.returncode}\n")
            f.write(f"STDOUT:\n{result.stdout}\n")
            f.write(f"STDERR:\n{result.stderr}\n")
        
        results[f'{service}_test'] = db_test_out
        print(f"{colors.GREEN}[+] {service.upper()} assessment completed: {db_test_out}{colors.END}")
        
    except Exception as e:
        print(f"{colors.RED}[-] {service.upper()} assessment error: {e}{colors.END}")
    
    return results if results else None

def system_security_check():
    """Check system security configuration"""
    print(f"\n{colors.MAGENTA}[!] Running System Security Checks...{colors.END}")
    
    try:
        # Download and run security assessment tools
        linpeas_url = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
        linpeas_path = f"{loot_dir}/linpeas.sh"
        
        # Download LinPEAS if not exists
        if not os.path.exists(linpeas_path):
            print(f"{colors.YELLOW}[*] Downloading LinPEAS...{colors.END}")
            try:
                r = requests.get(linpeas_url, timeout=30)
                with open(linpeas_path, 'wb') as f:
                    f.write(r.content)
                os.chmod(linpeas_path, 0o755)
                print(f"{colors.GREEN}[+] LinPEAS downloaded successfully{colors.END}")
            except Exception as e:
                print(f"{colors.RED}[-] Failed to download LinPEAS: {e}{colors.END}")
                return
        
        # Only run if we have permission (checking if we're on the target system)
        if sys.platform == "linux":
            print(f"{colors.YELLOW}[*] Running LinPEAS...{colors.END}")
            subprocess.run(f"{linpeas_path} > {loot_dir}/linpeas_output.txt", shell=True, timeout=300)
            print(f"{colors.GREEN}[+] LinPEAS output saved to {loot_dir}/linpeas_output.txt{colors.END}")
        
    except Exception as e:
        print(f"{colors.RED}[-] System security check error: {e}{colors.END}")

def generate_report(target, services, assessments, cloud_providers):
    report_file = get_next_filename()
    print(f"\n{colors.GREEN}[!] PHASE 3: REPORT GENERATION{colors.END}")
    
    with open(report_file, 'w') as f:
        f.write(f"""<!DOCTYPE html>
<html><head>
<title>Security Assessment Report for {target}</title>
<style>
    body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    h1 {{ color: #d33682; border-bottom: 3px solid #d33682; padding-bottom: 10px; }}
    h2 {{ color: #268bd2; border-bottom: 2px solid #268bd2; padding-bottom: 5px; }}
    h3 {{ color: #2aa198; }}
    .service {{ background: #fdf6e3; padding: 15px; margin: 10px 0; border-left: 4px solid #b58900; border-radius: 4px; }}
    .assessment {{ background: #eee8d5; padding: 15px; margin: 10px 0; border-left: 4px solid #cb4b16; border-radius: 4px; }}
    .vulnerability {{ background: #fdf2f2; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3545; border-radius: 4px; }}
    .cloud {{ background: #d33682; color: white; padding: 15px; margin: 10px 0; border-radius: 4px; }}
    .summary {{ background: #d4edda; padding: 15px; margin: 10px 0; border-left: 4px solid #28a745; border-radius: 4px; }}
    code {{ background: #f8f9fa; padding: 2px 4px; border-radius: 3px; font-family: monospace; }}
    .timestamp {{ color: #6c757d; font-size: 0.9em; }}
</style>
</head><body>
<div class="container">""")
        
        f.write(f"<h1>🔒 SECURITY ASSESSMENT REPORT</h1>")
        f.write(f"<div class='summary'>")
        f.write(f"<h2>📋 Executive Summary</h2>")
        f.write(f"<p><strong>Target:</strong> {target}</p>")
        f.write(f"<p><strong>Assessment Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
        f.write(f"<p><strong>Services Discovered:</strong> {len(services)}</p>")
        f.write(f"<p><strong>Assessments Performed:</strong> {len([a for a in assessments.values() if a])}</p>")
        f.write(f"</div>")
        
        if cloud_providers:
            f.write(f"<div class='cloud'>")
            f.write(f"<h3>☁️ Cloud Infrastructure Detected</h3>")
            for provider in cloud_providers:
                f.write(f"<p>🏢 {provider} services detected</p>")
            f.write(f"</div>")
        
        f.write("<h2>🔍 DISCOVERED SERVICES</h2>")
        if services:
            for port, data in services.items():
                f.write(f"<div class='service'>")
                f.write(f"<h3>🔌 Port {port}: {data['service']}</h3>")
                if data.get('version'):
                    f.write(f"<p><strong>Version:</strong> {data['version']}</p>")
                
                if data['vulnerabilities']:
                    f.write(f"<h4>⚠️ Potential Vulnerabilities:</h4>")
                    for vuln in data['vulnerabilities']:
                        f.write(f"<div class='vulnerability'>")
                        f.write(f"<p><strong>Script:</strong> {vuln.get('script', 'Unknown')}</p>")
                        f.write(f"<p><strong>Details:</strong> <code>{vuln.get('output', 'No details')[:200]}...</code></p>")
                        f.write(f"</div>")
                else:
                    f.write(f"<p>✅ No obvious vulnerabilities detected</p>")
                f.write("</div>")
        else:
            f.write("<p>No services discovered or scan failed.</p>")
        
        f.write("<h2>🔬 ASSESSMENT RESULTS</h2>")
        if any(assessments.values()):
            for port, result in assessments.items():
                if result:
                    f.write(f"<div class='assessment'>")
                    f.write(f"<h3>🔎 Port {port} Assessment Results</h3>")
                    for name, path in result.items():
                        f.write(f"<p><strong>{name.upper()}:</strong> <code>{path}</code></p>")
                    f.write("</div>")
        else:
            f.write("<p>No detailed assessments were performed or completed successfully.</p>")
        
        f.write("<h2>📁 EVIDENCE COLLECTED</h2>")
        f.write(f"<p>All assessment artifacts have been saved to:</p>")
        f.write(f"<ul>")
        f.write(f"<li><code>{exploit_dir}/</code> - Assessment results</li>")
        f.write(f"<li><code>{loot_dir}/</code> - Security analysis outputs</li>")
        f.write(f"</ul>")
        
        if os.path.exists(loot_dir):
            loot_files = os.listdir(loot_dir)
            if loot_files:
                f.write("<h3>📋 Evidence Files:</h3><ul>")
                for loot_file in loot_files:
                    f.write(f"<li><code>{loot_file}</code></li>")
                f.write("</ul>")
        
        f.write(f"<div class='timestamp'>")
        f.write(f"<p><em>Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}</em></p>")
        f.write(f"<p><em>⚠️ This assessment was performed for authorized security testing purposes only.</em></p>")
        f.write(f"</div>")
        
        f.write("</div></body></html>")
    
    return report_file

def main():
    show_banner()
    
    # Legal disclaimer
    print(f"{colors.RED}⚠️  LEGAL DISCLAIMER ⚠️{colors.END}")
    print(f"{colors.YELLOW}This tool is for authorized security testing only.{colors.END}")
    print(f"{colors.YELLOW}Ensure you have explicit permission before scanning any target.{colors.END}")
    print(f"{colors.YELLOW}Unauthorized scanning may violate laws and regulations.{colors.END}\n")
    
    if len(sys.argv) < 2:
        print(f"{colors.RED}Usage: python3 {sys.argv[0]} <target_ip_or_domain>{colors.END}")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate target format
    if not re.match(r'^[a-zA-Z0-9.-]+$', target):
        print(f"{colors.RED}[-] Invalid target format{colors.END}")
        sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    system_update()
    
    # Create directories
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(exploit_dir, exist_ok=True)
    os.makedirs(loot_dir, exist_ok=True)
    
    print(f"{colors.GREEN}[+] Starting security assessment of {target}...{colors.END}")
    
    # Phase 1: Discovery
    print(f"\n{colors.BLUE}[!] PHASE 1: DISCOVERY & ENUMERATION{colors.END}")
    services = run_nmap(target)
    cloud_providers = cloud_detection(target)
    
    # Phase 2: Assessment
    assessments = security_assessment(target, services)
    
    # Phase 3: System checks (only if local)
    system_security_check()
    
    # Phase 4: Reporting
    report_path = generate_report(target, services, assessments, cloud_providers)
    
    print(f"\n{colors.GREEN}[✓] Security assessment complete!{colors.END}")
    print(f"    {colors.CYAN}📄 HTML Report: {report_path}{colors.END}")
    print(f"    {colors.CYAN}📁 Assessment files: {exploit_dir}/{colors.END}")
    print(f"    {colors.CYAN}🔍 Analysis outputs: {loot_dir}/{colors.END}")
    print(f"\n{colors.YELLOW}Remember: Use this information responsibly and only on authorized targets.{colors.END}")

if __name__ == "__main__":
    main()
