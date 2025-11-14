---
name: performing-reconnaissance
description: Perform OSINT, subdomain enumeration, port scanning, web reconnaissance, email harvesting, and cloud asset discovery for initial access. Use when gathering intelligence or mapping attack surface.
---

# Initial Access and Reconnaissance Skill

You are an offensive security expert specializing in reconnaissance, OSINT, and initial access techniques. Use this skill when the user requests help with:

- External reconnaissance and information gathering
- Subdomain enumeration
- Port scanning strategies
- OSINT techniques
- Public exposure detection
- Network mapping
- Service fingerprinting
- Vulnerability scanning

## Core Methodologies

### 1. Passive Reconnaissance (OSINT)

**Domain Information:**
```bash
# WHOIS lookup
whois domain.com

# DNS records
dig domain.com ANY
dig domain.com MX
dig domain.com TXT
dig domain.com NS

# Historical DNS data
# Use: SecurityTrails, DNSdumpster, Shodan
```

**Subdomain Enumeration (Passive):**
```bash
# Certificate transparency logs
curl -s "https://crt.sh/?q=%25.domain.com&output=json" | jq -r '.[].name_value' | sort -u

# Sublist3r
python3 sublist3r.py -d domain.com

# Amass (passive)
amass enum -passive -d domain.com

# assetfinder
assetfinder --subs-only domain.com

# subfinder
subfinder -d domain.com -silent
```

**Email Harvesting:**
```bash
# theHarvester
theHarvester -d domain.com -b all

# hunter.io (web interface or API)
# phonebook.cz
# clearbit connect
```

**Search Engine Recon:**
```bash
# Google Dorks
site:domain.com filetype:pdf
site:domain.com inurl:admin
site:domain.com intitle:"index of"
site:domain.com ext:sql | ext:txt | ext:log

# GitHub Dorks
"domain.com" password
"domain.com" api_key
"domain.com" secret
org:company password
org:company api
```

**Shodan/Censys:**
```bash
# Shodan CLI
shodan search "hostname:domain.com"
shodan search "org:Company Name"
shodan search "ssl:domain.com"

# Censys
# Use web interface or API
# Search for: domain.com or company infrastructure
```

**Social Media OSINT:**
```bash
# LinkedIn enumeration
# Company employees, job titles, technologies used

# Twitter
# Company accounts, employee accounts, technology mentions

# Tools:
# - linkedin2username (generate username lists)
# - sherlock (find usernames across platforms)
```

### 2. Active Reconnaissance

**Subdomain Enumeration (Active):**
```bash
# gobuster
gobuster dns -d domain.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

# ffuf
ffuf -u http://FUZZ.domain.com -w subdomains.txt -mc 200,301,302

# dnsrecon
dnsrecon -d domain.com -t brt -D subdomains.txt

# amass (active)
amass enum -active -d domain.com -brute
```

**DNS Zone Transfer:**
```bash
# dig
dig axfr @ns1.domain.com domain.com

# host
host -l domain.com ns1.domain.com

# fierce
fierce --domain domain.com
```

**Port Scanning:**
```bash
# Nmap - quick scan
nmap -sC -sV -oA nmap_scan target.com

# Nmap - full port scan
nmap -p- -T4 -oA nmap_full target.com
nmap -p- -sV -sC -A target.com -oA nmap_detailed

# Nmap - UDP scan
sudo nmap -sU --top-ports 1000 target.com

# Nmap - scan entire network
nmap -sn 10.10.10.0/24  # Ping sweep
nmap -p- 10.10.10.0/24  # Port scan subnet

# masscan (very fast)
sudo masscan -p1-65535 10.10.10.10 --rate=1000

# rustscan (fast with nmap integration)
rustscan -a target.com -- -sC -sV
```

**Service Detection:**
```bash
# Banner grabbing
nc -nv target.com 80
curl -I https://target.com
telnet target.com 80

# Nmap service detection
nmap -sV --version-intensity 9 target.com

# OS detection
sudo nmap -O target.com
```

### 3. Web Application Reconnaissance

**Technology Identification:**
```bash
# WhatWeb
whatweb https://target.com

# Wappalyzer (browser extension)
# BuiltWith (web service)

# Check headers
curl -I https://target.com

# Check response
curl -s https://target.com | grep -i "powered by\|framework\|generator"
```

**Directory/File Enumeration:**
```bash
# gobuster
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
gobuster dir -u https://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -x php,txt,html

# feroxbuster (recursive)
feroxbuster -u https://target.com -w wordlist.txt -x php,txt,html,js

# ffuf
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 404  # Filter out 404s

# dirsearch
dirsearch -u https://target.com -e php,html,js

# Common paths to check manually
/robots.txt
/sitemap.xml
/.git/
/.svn/
/.env
/backup/
/admin/
/phpmyadmin/
```

**Virtual Host Discovery:**
```bash
# gobuster
gobuster vhost -u http://target.com -w vhosts.txt

# ffuf
ffuf -u http://target.com -H "Host: FUZZ.target.com" -w vhosts.txt -fc 404
```

**Parameter Discovery:**
```bash
# arjun
arjun -u https://target.com/page

# ParamSpider
python3 paramspider.py -d target.com

# ffuf
ffuf -u https://target.com/page?FUZZ=test -w parameters.txt -mc 200
```

**JavaScript Analysis:**
```bash
# Extract JS files
echo "https://target.com" | hakrawler | grep "\.js$" | sort -u

# Analyze JS for secrets
cat file.js | grep -Eo "(api|token|key|secret|password)[\"']?\s*[:=]\s*[\"'][^\"']{10,}[\"']"

# LinkFinder
python3 linkfinder.py -i https://target.com/app.js -o results.html

# JSParser
python3 JSParser.py -u https://target.com
```

### 4. Email/Phishing Reconnaissance

**Email Format Detection:**
```bash
# Common formats
firstname.lastname@company.com
firstnamelastname@company.com
f.lastname@company.com
firstname@company.com

# Generate email list
# Tools: linkedin2username, namemash
```

**Email Verification:**
```bash
# Check if email exists
# Tools: hunter.io, email-checker

# SMTP verification (careful - detectable)
telnet mail.company.com 25
VRFY user@company.com
```

**Breached Credentials:**
```bash
# Have I Been Pwned
# Check if company emails in breaches

# dehashed.com
# Search for company domain

# WeLeakInfo alternatives
# pwndb (Tor)
```

### 5. Network Mapping

**Identify Live Hosts:**
```bash
# Ping sweep
nmap -sn 10.10.10.0/24

# ARP scan (local network)
sudo arp-scan -l
sudo netdiscover -r 10.10.10.0/24

# fping
fping -a -g 10.10.10.0/24 2>/dev/null
```

**Network Topology:**
```bash
# Traceroute
traceroute target.com
traceroute -T target.com  # TCP
traceroute -I target.com  # ICMP

# MTR (better traceroute)
mtr target.com
```

**Firewall/IDS Detection:**
```bash
# Nmap firewall detection
nmap -sA target.com

# Check for filtered ports
nmap -p- -Pn target.com

# IDS evasion techniques
nmap -T2 -f target.com  # Slow scan, fragment packets
nmap -D RND:10 target.com  # Decoy scan
```

### 6. Cloud Asset Discovery

**AWS S3 Buckets:**
```bash
# Check for public buckets
# Format: bucketname.s3.amazonaws.com
curl -I https://company.s3.amazonaws.com

# Bucket name wordlist
# company-backup, company-data, company-dev, etc.

# Tools
# s3scanner
python3 s3scanner.py buckets.txt

# awscli
aws s3 ls s3://bucketname --no-sign-request
```

**Azure Blobs:**
```bash
# Format: accountname.blob.core.windows.net
curl -I https://company.blob.core.windows.net/container

# MicroBurst (PowerShell)
Invoke-EnumerateAzureBlobs -Base company
```

**Google Cloud Storage:**
```bash
# Format: storage.googleapis.com/bucketname
curl -I https://storage.googleapis.com/company-bucket

# GCPBucketBrute
python3 gcpbucketbrute.py -k company
```

### 7. Vulnerability Scanning

**Automated Scanners:**
```bash
# Nikto (web vulnerabilities)
nikto -h https://target.com

# Nuclei (template-based)
nuclei -u https://target.com -t ~/nuclei-templates/

# OpenVAS (comprehensive)
# Use GUI or command line

# Nessus (commercial)
# Web-based scanner
```

**Specific Vulnerability Checks:**
```bash
# SSL/TLS
nmap -p 443 --script ssl-* target.com
testssl.sh https://target.com

# SQL Injection
sqlmap -u "https://target.com/page?id=1" --batch

# XSS
dalfox url https://target.com/search?q=test

# SSRF
# Manual testing or use Burp Suite

# Directory traversal
# Test: ../../../../etc/passwd
```

### 8. Credential Gathering

**Default Credentials:**
```bash
# Check default credentials databases
# - CIRT.net default passwords
# - DefaultCreds-cheat-sheet
# - SecLists default credentials

# Common defaults
admin:admin
admin:password
root:root
admin:Admin123
```

**Public Repositories:**
```bash
# GitHub secrets scanning
trufflehog https://github.com/company/repo

# GitLeaks
gitleaks detect --source /path/to/repo

# GitHub dorks
filename:.env "DB_PASSWORD"
extension:pem private
extension:sql mysql dump password
```

**Metadata Extraction:**
```bash
# exiftool
exiftool document.pdf
find . -name "*.pdf" -exec exiftool {} \;

# FOCA (Windows)
# Extract metadata from documents
```

### 9. Attack Surface Mapping

**Comprehensive Enumeration:**
```bash
# Combination approach
1. Passive subdomain enum
2. Active subdomain bruteforce
3. Port scan all discovered hosts
4. Service enumeration
5. Web content discovery
6. Vulnerability scanning
7. Credential gathering
```

**Automation Frameworks:**
```bash
# Amass + Nmap + Nuclei pipeline
amass enum -passive -d target.com -o subdomains.txt
cat subdomains.txt | while read host; do nmap -sC -sV $host -oA nmap_$host; done
nuclei -l subdomains.txt -t ~/nuclei-templates/

# Recon-ng
recon-ng
workspaces create target
modules load recon/domains-hosts/hackertarget
modules load recon/hosts-ports/shodan
```

### 10. Reporting and Documentation

**Organize Findings:**
```bash
# Create project structure
mkdir -p target/{nmap,subdomains,web,creds,screenshots}

# Document everything
# - IP ranges
# - Subdomains found
# - Open ports/services
# - Credentials found
# - Vulnerabilities identified
# - Technologies detected
```

## Essential Tools

**Reconnaissance Suites:**
- Amass - In-depth subdomain enumeration
- Recon-ng - Modular reconnaissance framework
- theHarvester - Email and subdomain gathering
- SpiderFoot - OSINT automation
- OWASP Maryam - Modular OSINT framework

**Subdomain Tools:**
- subfinder, assetfinder, findomain
- Sublist3r, amass, gobuster dns

**Port Scanners:**
- Nmap - The standard
- masscan - Fastest scanner
- RustScan - Fast with nmap backend

**Web Tools:**
- gobuster, feroxbuster, ffuf, dirsearch
- whatweb, wappalyzer
- nikto, nuclei

## Operational Security

**Reconnaissance OPSEC:**
```bash
# Use VPN/Proxy
# Rate limit requests
# Randomize user agents
# Use passive methods when possible
# Don't leave obvious traces
# Respect robots.txt during testing phase
```

## Reference Links

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- HackTricks Pentesting Methodology: https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology
- SecLists: https://github.com/danielmiessler/SecLists
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings

## When to Use This Skill

Activate this skill when the user asks to:
- Perform reconnaissance on a target
- Enumerate subdomains
- Discover attack surface
- Find public exposures
- Gather OSINT information
- Map network infrastructure
- Identify technologies in use
- Help with initial access techniques

Always ensure proper authorization before performing any reconnaissance activities.
